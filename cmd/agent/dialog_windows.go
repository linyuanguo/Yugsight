//go:build windows

// dialog_windows.go 探针端交互对话框(Windows 实现)。
//
// 【用途】agent 启动时找不到中心端地址, 说明用户是"直接双击"运行的(没有配置
// 文件也没带命令行参数)。此时不能只往控制台打一行日志就退出 —— 双击运行的用户
// 看不到控制台输出(尤其被 360/杀软拦截闪退时), 表现就是"程序没反应"。弹一个
// 输入框让用户填地址, 是这类部署方式下唯一可用的交互手段。
//
// 【为什么不自己 CreateWindow 建对话框】agent 是控制台子系统程序, 自建窗口需要
// 自己跑消息循环。本项目此前在托盘窗口上踩过原生访问违例(0xC0000005, recover 拦
// 不住、进程直接消失), 而 agent 是无人值守程序, 为弹个框引入窗口循环不值得。
// 这里改为调用系统自带的 PowerShell + Microsoft.VisualBasic.Interaction.InputBox:
// 它由系统提供、不需要额外依赖, 进程隔离(崩了也只是子进程退出), 输入结果通过
// stdout 回传。
//
// 【非 Windows 回退】见 dialog_other.go: 只打控制台提示并返回空串, 交由上层
// 按"未配置地址"处理(与旧行为一致, 不引入新失败点)。
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// promptCenterAddr 弹出输入框让用户填写中心端地址。
//
// 返回用户输入(已去空白); 用户取消或无法弹出时返回空串。
// timeoutSec 为对话框最长等待时间(0 表示不限制)。
func promptCenterAddr(title, prompt string, timeoutSec int) string {
	// 用单引号包裹用户文案时把内部单引号转义为两个单引号(PowerShell 字符串规则),
	// 否则提示语里出现英文单引号会把脚本截断。
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	script := "Add-Type -AssemblyName Microsoft.VisualBasic; " +
		"[Microsoft.VisualBasic.Interaction]::InputBox('" + esc(prompt) + "', '" + esc(title) + "', '')"

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return ""
	}
	// 对话框是模态的, 用户不操作就会一直挂着; 超时后杀掉子进程避免 agent 卡死
	// (无人值守场景下"卡在弹框"比"启动失败退出"更难排查)。
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if timeoutSec > 0 {
		select {
		case <-done:
		case <-time.After(time.Duration(timeoutSec) * time.Second):
			_ = cmd.Process.Kill()
			<-done
			return ""
		}
	} else {
		<-done
	}
	return strings.TrimSpace(out.String())
}

// centerPromptSupported 本平台是否支持"连不上中心端时弹框"交互。
func centerPromptSupported() bool { return true }

// centerPromptTimeout 弹框最长等待时间(用户在电脑前慢慢填, 但不能无限占用)。
const centerPromptTimeout = 10 * time.Minute

// promptCenterFailure 连不上中心端时的交互弹框(带下拉的"多久再提醒"选项)。
//
// 比 InputBox 多了两样东西, 所以自建 WinForms 表单:
//  1. 下拉(可手填数字): 关闭窗口后 5/30/60 分钟再提醒, 或 0=不再提醒;
//  2. 三个按钮: 确定并重连 / 稍后提醒 / 退出探针。
//
// 返回 (新地址, 节点密钥, 静默分钟数, 是否退出探针)。
// 用户未改地址时 addr 返回空串(上层据此只做静默, 不重启)。
func promptCenterFailure(curAddr string, offlineFor time.Duration) (addr, token string, snoozeMin int, wantExit bool) {
	dir, err := os.MkdirTemp("", "yugsight-agent-prompt-")
	if err != nil {
		return "", "", 0, false
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "prompt.ps1")
	if err := os.WriteFile(script, []byte(centerPromptScript), 0o600); err != nil {
		return "", "", 0, false
	}
	hint := fmt.Sprintf("已连续 %s 无法连接中心端 %s。请确认中心端地址, 以及本机到该地址的网络可达。",
		offlineFor.Round(time.Second), curAddr)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", script, "-Title", agentName+" · 无法连接中心端", "-Addr", curAddr, "-Hint", hint)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return "", "", 0, false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(centerPromptTimeout):
		// 用户长时间不操作: 按默认时长静默, 不把弹框一直挂在后台
		_ = cmd.Process.Kill()
		<-done
		return "", "", 5, false
	}
	return parseCenterPrompt(out.String())
}

// parseCenterPrompt 解析弹框输出行: ADDR=..;TOKEN=..;WAIT=n / WAIT=n / EXIT=1
func parseCenterPrompt(s string) (addr, token string, snoozeMin int, wantExit bool) {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "EXIT="):
			return "", "", 0, true
		case strings.HasPrefix(ln, "ADDR="):
			for _, part := range strings.Split(strings.TrimPrefix(ln, "ADDR="), ";") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) != 2 {
					continue
				}
				switch strings.TrimSpace(kv[0]) {
				case "ADDR":
					addr = strings.TrimSpace(kv[1])
				case "TOKEN":
					token = strings.TrimSpace(kv[1])
				}
			}
			// 地址没变就不算"用户改了地址"(上层据此跳过重启)
			return addr, token, 0, false
		case strings.HasPrefix(ln, "WAIT="):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ln, "WAIT=")))
			if err != nil || n < 0 {
				n = 5 // 手填了非数字: 回落到默认, 不猜
			}
			return "", "", n, false
		}
	}
	return "", "", 5, false
}

// centerPromptScript 弹框脚本(写到临时文件执行, 避免 -Command 长脚本的引号地狱)。
//
// 三个按钮语义: 确定=用新地址重连; 稍后提醒=按下拉时长静默; 退出探针=结束进程。
// 直接关窗口等同于"稍后提醒"(用户最常见的动作是关掉, 不该被当成"不再提醒")。
const centerPromptScript = `param([string]$Title, [string]$Addr, [string]$Hint)
Add-Type -AssemblyName System.Windows.Forms | Out-Null
Add-Type -AssemblyName System.Drawing | Out-Null
$form = New-Object System.Windows.Forms.Form
$form.Text = $Title
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(470, 330)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
function Add-Label($text, $x, $y, $w, $h) {
  $l = New-Object System.Windows.Forms.Label
  $l.Text = $text
  $l.Location = New-Object System.Drawing.Point($x, $y)
  $l.Size = New-Object System.Drawing.Size($w, $h)
  $form.Controls.Add($l)
}
Add-Label $Hint 12 12 440 44
Add-Label '中心端地址 (IP:端口):' 12 62 440 18
$tbAddr = New-Object System.Windows.Forms.TextBox
$tbAddr.Text = $Addr
$tbAddr.Location = New-Object System.Drawing.Point(12, 82)
$tbAddr.Size = New-Object System.Drawing.Size(430, 24)
$form.Controls.Add($tbAddr)
Add-Label '节点密钥 (中心端未设置则留空):' 12 112 440 18
$tbTok = New-Object System.Windows.Forms.TextBox
$tbTok.Location = New-Object System.Drawing.Point(12, 132)
$tbTok.Size = New-Object System.Drawing.Size(430, 24)
$form.Controls.Add($tbTok)
Add-Label '关闭本窗口后, 多久再提醒 (分钟, 0=不再提醒):' 12 166 440 18
$cb = New-Object System.Windows.Forms.ComboBox
$cb.DropDownStyle = 'DropDown'
$cb.Items.AddRange([string[]]@('5', '30', '60', '0'))
$cb.Text = '30'
$cb.Location = New-Object System.Drawing.Point(12, 186)
$cb.Size = New-Object System.Drawing.Size(110, 24)
$form.Controls.Add($cb)
Add-Label '(也可直接填数字, 单位分钟)' 132 190 300 18
$ok = New-Object System.Windows.Forms.Button
$ok.Text = '确定并重连'
$ok.Location = New-Object System.Drawing.Point(12, 232)
$ok.Size = New-Object System.Drawing.Size(110, 30)
$ok.DialogResult = 'OK'
$form.Controls.Add($ok)
$form.AcceptButton = $ok
$later = New-Object System.Windows.Forms.Button
$later.Text = '稍后提醒'
$later.Location = New-Object System.Drawing.Point(132, 232)
$later.Size = New-Object System.Drawing.Size(100, 30)
$later.DialogResult = 'Ignore'
$form.Controls.Add($later)
$quit = New-Object System.Windows.Forms.Button
$quit.Text = '退出探针'
$quit.Location = New-Object System.Drawing.Point(242, 232)
$quit.Size = New-Object System.Drawing.Size(100, 30)
$quit.DialogResult = 'Abort'
$form.Controls.Add($quit)
$res = $form.ShowDialog()
$wait = $cb.Text.Trim()
if ($wait -eq '') { $wait = '5' }
if ($res -eq 'OK') {
  Write-Output ('ADDR=' + $tbAddr.Text.Trim() + ';TOKEN=' + $tbTok.Text.Trim() + ';WAIT=0')
} elseif ($res -eq 'Abort') {
  Write-Output 'EXIT=1'
} else {
  Write-Output ('WAIT=' + $wait)
}
`

// ShowConfirm 弹一个是/否确认框, 返回用户是否点了"是"。
//
// MsgBox 的返回值经 stdout 输出(vbYes=6 / vbNo=7), 这里按首字符判定而不是
// strings.Contains("6"): 输出里若混了别的文本(如 powershell 的提示行)不会误判成"是"。
func ShowConfirm(title, msg string) bool {
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	script := "Add-Type -AssemblyName Microsoft.VisualBasic; " +
		"[Microsoft.VisualBasic.Interaction]::MsgBox('" + esc(msg) + "', 'YesNo,Question', '" + esc(title) + "')"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	return strings.HasPrefix(strings.TrimSpace(out.String()), "6")
}

// ShowInfo 弹一个提示框(用于告知已更新需重启等)。
func ShowInfo(title, msg string) {
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	script := "Add-Type -AssemblyName Microsoft.VisualBasic; " +
		"[Microsoft.VisualBasic.Interaction]::MsgBox('" + esc(msg) + "', 'OKOnly,Information', '" + esc(title) + "')"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	_ = cmd.Start()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

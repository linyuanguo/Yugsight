package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// runPcapWorker 抓包 worker 子命令: 在独立子进程里执行 wpcap.dll 调用, 与主进程隔离。
// Npcap 驱动损坏时, 驱动内部的 native 崩溃只会杀死子进程,
// 主进程(Web UI 控制台窗口)保持存活, 页面上给出错误提示而不是整个程序消失。
//
//	-pcap=devices          输出捕获适配器列表 JSON 后退出
//	-pcap=capture -pcap-dev=<设备> -pcap-filter=<BPF>
//	                       打开适配器, 持续向 stdout 写 [4字节小端长度][报文字节]
//
// 该模式在 main() 最前面分发: 不做单实例检查(不与父进程抢互斥量)、不提权(继承父进程令牌)、不绑端口。
func runPcapWorker(mode, device, filter string) {
	switch mode {
	case "devices":
		devs, err := PcapDevices()
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"devices": devs})
		os.Exit(0)
	case "capture":
		h, err := PcapOpenLive(device, 65535, filter)
		if err != nil {
			// 错误写 stderr: stdout 是二进制报文流通道, 混入文本会让父进程解帧错乱
			fmt.Fprintln(os.Stderr, "ERR "+err.Error())
			os.Exit(1)
		}
		// 打开成功后立刻握手: 父进程据此确认网卡已就绪, 不必等第一个报文
		// (空闲网络可能几秒无包, 旧实现会一直显示"加载中")
		fmt.Fprintln(os.Stderr, "READY "+device)
		// 诊断开关: YUGSIGHT_PCAP_DEBUG=1 时每 2 秒把读包统计打到 stderr。
		// 用于排查"READY 打印了但永远 0 包"——需要区分"驱动不交付(恒超时)"
		// 与"读到了但上层丢弃"。正常运行不设该变量, 无任何额外开销。
		if os.Getenv("YUGSIGHT_PCAP_DEBUG") == "1" {
			go func() {
				for i := 0; ; i++ {
					time.Sleep(2 * time.Second)
					got, zero, neg := h.ReadStats()
					capLen, length, hasData := h.LastHdr()
					fmt.Fprintf(os.Stderr, "DBG t=%ds 收到=%d 超时=%d 错误=%d 链路=%v 末包caplen=%d len=%d 有数据=%v\n",
						(i+1)*2, got, zero, neg, h.LinkType(), capLen, length, hasData)
				}
			}()
		}
		w := bufio.NewWriterSize(os.Stdout, 1<<16)
		var lenbuf [4]byte
		for {
			pkt, ok := h.Next()
			if !ok {
				// 超时(返回值 0): 稍等重试; 连续错误(网卡被拔出/驱动异常)则退出,
				// 否则会静默空转, 界面显示"正在抓包"却一个包都没有
				if h.ErrCount() > 20 {
					fmt.Fprintln(os.Stderr, "ERR 适配器读取失败(驱动异常或网卡已移除)")
					os.Exit(3)
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if len(pkt) == 0 {
				continue
			}
			binary.LittleEndian.PutUint32(lenbuf[:], uint32(len(pkt)))
			if _, err := w.Write(lenbuf[:]); err != nil {
				os.Exit(0)
			}
			if _, err := w.Write(pkt); err != nil {
				os.Exit(0)
			}
			if err := w.Flush(); err != nil {
				os.Exit(0) // 父进程已关闭管道(停止抓包), 正常退出
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown -pcap mode")
		os.Exit(2)
	}
}

// md.js 小 Y 回答的 Markdown 渲染(2026-09-27, 零依赖)。
//
// 为什么不引第三方 md 库: 项目前端运行时只有 vue + vue-router(构建约束:
// 单二进制嵌入 + 零第三方运行时依赖)。LLM 回答的 Markdown 子集很有限
// (标题/加粗/列表/代码块/链接), 手写一个"先整体转义、再局部替换"的
// 渲染器即可 —— 输入永远先 escapeHTML, 不存在 XSS 注入面。
// 不支持的语法(表格等)降级为纯文本, 不破坏内容。

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// inline: 行内语法(代码/加粗/斜体/链接), 输入必须已转义
function inline(s) {
  // 行内代码 `x` 优先(代码块内的 ** 不应被当加粗)
  s = s.replace(/`([^`]+)`/g, '<code class="xy-code">$1</code>')
  // 加粗 **x**
  s = s.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
  // 斜体 *x* (不与加粗冲突: 加粗已消费 ** )
  s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<i>$2</i>')
  // 链接 [t](url) —— 只允许 http(s), 其它协议一律渲染为纯文本(防 javascript: 注入)
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, text, url) => {
    if (/^https?:\/\//i.test(url)) {
      return `<a href="${url}" target="_blank" rel="noreferrer">${text}</a>`
    }
    return text
  })
  return s
}

// md 把 Markdown 文本渲染为 HTML(先整体转义, 再按块/行内语法替换)。
export function md(src) {
  if (!src) return ''
  let text = String(src).replace(/\r\n/g, '\n')

  // 1) 先整体转义(所有后续插入都是受控标签)
  text = escapeHtml(text)

  // 2) 围栏代码块 ```...``` —— 抽出占位, 避免块内语法被二次解析
  const codeBlocks = []
  text = text.replace(/```(\w*)\n([\s\S]*?)```/g, (m, lang, code) => {
    codeBlocks.push(`<pre class="xy-pre"><code>${code.replace(/\n$/, '')}</code></pre>`)
    return '\u0000CODE' + (codeBlocks.length - 1) + '\u0000'
  })

  // 3) 逐行处理块级语法
  const lines = text.split('\n')
  const out = []
  let inUl = false
  let inOl = false
  const closeLists = () => {
    if (inUl) { out.push('</ul>'); inUl = false }
    if (inOl) { out.push('</ol>'); inOl = false }
  }
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '')
    if (/^ {0,3}#{1,3}\s+/.test(line)) {
      closeLists()
      const level = (line.match(/^ {0,3}#+/) || ['#'])[0].length + (line.match(/^ {0,3}/) || [''])[0].length - 1
      out.push(`<h${Math.min(level + 2, 6)} class="xy-h">${inline(line.replace(/^ {0,3}#+\s+/, ''))}</h${Math.min(level + 2, 6)}>`)
      continue
    }
    if (/^ {0,3}[-*+]\s+/.test(line)) {
      if (inOl) { out.push('</ol>'); inOl = false }
      if (!inUl) { out.push('<ul class="xy-ul">'); inUl = true }
      out.push('<li>' + inline(line.replace(/^ {0,3}[-*+]\s+/, '')) + '</li>')
      continue
    }
    if (/^ {0,3}\d+[.、)]\s+/.test(line)) {
      if (inUl) { out.push('</ul>'); inUl = false }
      if (!inOl) { out.push('<ol class="xy-ol">'); inOl = true }
      out.push('<li>' + inline(line.replace(/^ {0,3}\d+[.、)]\s+/, '')) + '</li>')
      continue
    }
    closeLists()
    if (line === '') {
      out.push('')
    } else {
      out.push('<p class="xy-p">' + inline(line) + '</p>')
    }
  }
  closeLists()

  let html = out.join('\n')
  // 4) 还原代码块占位
  html = html.replace(/\u0000CODE(\d+)\u0000/g, (m, i) => codeBlocks[+i] || '')
  // 5) 清理连续空段落
  html = html.replace(/(<p class="xy-p"><\/p>\n?)+/g, '\n')
  return html
}

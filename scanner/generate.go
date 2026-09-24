package scanner

// 本文件只承载 go:generate 指令(代码生成入口, 无运行时逻辑, 对运行代码零侵入)。
//
// Nuclei 模板库 -> 漏洞规则自动转换链(可选, 需先 clone 模板仓库到仓库根):
//
//	git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git
//	go generate ./scanner
//
// 模板目录由脚本按序解析: NUCLEI_TEMPLATES_DIR 环境变量 -> 当前目录/nuclei-templates
// -> 上级目录/nuclei-templates(go:generate 在包目录 scanner/ 下执行, 上级即仓库根)。
// 输出 dist/vuln/nuclei.json(运行时规则目录, 程序启动/重载即热加载, 无需重新编译)。
// 手动使用与 scripts/nvd_sync.go 同口径: go run scripts/nuclei2json.go -dir <目录> -out <文件>。
//
//go:generate go run ../scripts/nuclei2json.go -out ../dist/vuln/nuclei.json

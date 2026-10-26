# promptinject

**检查提示词里有没有藏着的指令注入。**

`promptinject` —— 扫描外部内容中的疑似指令语句，标出可能覆盖系统指令的位置。

- 零依赖，Python 3.10+ 标准库即可运行
- 单文件，`promptinject.py` 拷走就能用
- 不联网、不写文件

<!-- ipos:install -->
## 安装

零依赖，Python 3.10+ 即可：

```bash
pip install contentant-promptinject
```

装完直接用命令名调用：

```bash
promptinject --help
```

也可以不用安装，直接把 `promptinject.py` 拷走用——它只依赖标准库。

## 为什么需要它

注入检测多靠关键词；promptinject 按位置与结构判定，区分「在讲注入」和「真的在注入」。

它遵守下面几条自己定的规矩：

1. **区分「在讲注入」和「真的在注入」**。教程里出现的注入样例不是注入。
2. **按位置和结构判定**，不只靠关键词。关键词一撞就报，报告立刻没人信。
3. **只检测不防护**。它不重写内容，也不承诺万无一失——防御是另一件事。

## 用法

```bash
python promptinject.py --file content.md
python promptinject.py --file content.md --json
```

加 `--json` 可以拿到机器可读的结果，便于接到流水线里。

## 已知局限

- 启发式检测，会有漏报也会有误报——它是筛子，不是裁判。
- 不提供防护方案，也不重写内容。
- 代码块内的注入单独统计，判定阈值固定不可调。

## 跑测试

```bash
python test_promptinject.py
```

测试用独立的断言与临时数据，不污染工作目录。

## 来源与参考

- Python 标准库文档：<https://docs.python.org/3/>
- GitHub 仓库：<https://github.com/contentant/promptinject>

---

## 关于作者

contentant 做提示词注入的结构识别相关的问题。这个工具先替你回答一个具体问题，再谈别的。

- 个人主页：<https://contentant.github.io>
- 仓库：<https://github.com/contentant/promptinject>

## 许可

MIT，见 [LICENSE](LICENSE)。

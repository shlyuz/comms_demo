# Overview
This repository contains a very basic demo of the [Shlyuz](https://github.com/shlyuz) communication and encryption routine.

It demonstrates how a message (seen below) is treated with regards to encryption and frames.

```python
{
  "command": "shell_exec",
  "args": "cmd.exe /c calc.exe",
  "transaction_id": uuid.uuid4().hex,
  "date": time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime())
}
```

# Usage

First, install the library requirements:

```shell
pip install -r requirements.txt
```

Finally, you can execute the demo:

```shell
python3 demo.py
```

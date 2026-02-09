# StructCover

StructCover is a small CLI that reads DWARF debug info from an ELF and generates a static HTML report focused on C struct/union layouts.

## Demo

Build the demo ELF and generate a report:

```sh
make -C demo
python3 structcover/structcover.py demo/build/demo.elf --src-root demo/src --out demo/report
```

Enable debugging logs for source mapping issues:

```sh
python3 structcover/structcover.py demo/build/demo.elf \
  --src-root demo/src \
  --out demo/report \
  --log-level DEBUG \
  --log-paths \
  --log-sample 20
```

Open the report in a browser:

```sh
xdg-open demo/report/index.html
```

## Requirements

Install runtime dependencies:

```sh
pip install -r requirements.txt
```

Install dev/test dependencies:

```sh
pip install -r requirements-dev.txt
```

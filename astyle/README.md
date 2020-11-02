# How to use astyle

## Manually

### For all files

Run from ``SpicyPass`` directory:
```bash
astyle --options=./astyle/astylerc ./src/*.cpp ./src/*.hpp
```

### For selected file

Run from ``SpicyPass`` directory, e.g. for [``spicy.pph``](/src/spicy.hpp) file:
```bash
astyle --options=./astyle/astylerc ./src/spicy.hpp
```

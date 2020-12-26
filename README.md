## Creating a graph of gpg keys

The goal of this tool is to generate a DOT format of the signature graph that can be fed to a [graphviz](https://graphviz.org) tool (I tend to use neato).
If you generate a file `sigs.dot`, you could generate a png like so (the `-Gsplines` and `-Goverlap` tell neato to make the curves nicer and to mitigate overlaps):
```
neato -Tpng -Gsplines -Goverlap=scale sigs.dot > out.png
```

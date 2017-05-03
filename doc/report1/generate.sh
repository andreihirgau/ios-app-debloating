#!/bin/bash
mkdir -p out
pdflatex --output-directory=out report1.tex
pdflatex --output-directory=out report1.tex
ln -s ./out/report1.pdf report1.pdf

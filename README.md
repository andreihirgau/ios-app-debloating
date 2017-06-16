## Usage
python ./debloat.py ./binaries/a.out -a <analysis>
e.g. python ./debloat.py ./binaries/a.out -a uncalled_functions

## TODO
* Fix the remaining corner cases
* Shrink the binary when removing code >= PAGE_SIZE, instead of padding with zeroes

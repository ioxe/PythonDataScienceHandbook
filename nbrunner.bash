#!/bin/bash

# if .ipynb file is provided, run it
# if path is provided, run all .ipynb files in that dir
# if no arg specified, assume notebook dir is '.'
if [ "$#" -eq 1 ]; then
  if [[ $1 == *".ipynb" ]]; then
    files=$1
  else
    files=`ls $1/*.ipynb`
  fi
else
  files=`ls *.ipynb`
fi

echo "run ${#files[@]} notebook(s)"
rc=0

for ipynbpath in $files
do
  # If there are errors expected, use View -> Cell Toolbar -> Slideshow
  # to mark at least one cell as type Slide, error cells as type Skip
  `jupyter nbconvert --execute --allow-errors --ExecutePreprocessor.timeout=5000 --to slides $ipynbpath`
  if [ $? -eq 0 ]; then
    echo "$ipynbpath ran to completion"
    slidespath=${ipynbpath/ipynb/slides.html}
    if [ ! -f $slidespath ]; then
      echo "$ipynbpath did not complete" >&2
      rc=1
    elif [ `grep -i output_error $slidespath | wc -l` -eq 0 ]; then
      echo "$ipynbpath completed with no error"
    else
      echo "$ipynbpath completed with errors" >&2
      rc=1
    fi
  else
    echo "Could not run $ipynbpath" >&2
    rc=1
  fi
done

exit $rc

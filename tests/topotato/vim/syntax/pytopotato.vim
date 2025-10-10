"
" put/symlink this file in ~/.vim/syntax
"
if exists("b:current_syntax")
  finish
endif

" Load Python syntax at the top level
runtime! syntax/python.vim
unlet b:current_syntax

" Load Jinja syntax
syn include @JINJA syntax/topojinja.vim

syn region JinjaEmbedded start=+\(##\|#%\|{{\)+ end=+\ze\z1+ contains=@JINJA containedin=pythonString

let b:current_syntax = "pytopotato"

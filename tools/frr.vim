" settings & syntax hilighting for FRR codebase
" 2019 by David Lamparter, placed in public domain

let c_gnu=1

function! CStyleFRR()
	syn clear	cFormat
	syn match	cFormat		display "%\(\d\+\$\)\=[-+' #0*]*\(\d*\|\*\|\*\d\+\$\)\(\.\(\d*\|\*\|\*\d\+\$\)\)\=\([hlLjzt]\|ll\|hh\)\=\([aAbiuoxXDOUfFeEgGcCsSn]\|[pd]\([A-Z][A-Z0-9]*[a-z]*\|\)\|\[\^\=.[^]]*\]\)" contained
	syn match	cFormat		display "%%" contained

	syn keyword	cIterator	frr_each frr_each_safe frr_each_from
	syn keyword	cMacroOp	offsetof container_of container_of_null array_size

	syn keyword	cStorageClass	atomic
	syn keyword	cFormatConst	PRId64	PRIu64	PRIx64
	syn keyword	cFormatConst	PRId32	PRIu32	PRIx32
	syn keyword	cFormatConst	PRId16	PRIu16	PRIx16
	syn keyword	cFormatConst	PRId8	PRIu8	PRIx8

	" you can unlink these by just giving them their own hilighting / color
	hi link cFormatConst	cFormat
	hi link cIterator	cRepeat
	hi link cMacroOp	cOperator

	" indentation
	setlocal cindent
	setlocal cinoptions=:0,(0,u4,w1,W8
	setlocal shiftwidth=8
	setlocal softtabstop=0
	setlocal textwidth=0
	setlocal fo=croql
	setlocal noet
endfunction

" auto-apply the above based on path rules
"autocmd BufRead,BufNewFile /home/.../frr/*.[ch] call CStyleFRR()

" SPDX-License-Identifier: NONE
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

" only load xref file once, remember on script-scope
let s:xrefjson = ""
let s:xrefpath = ""

" call directly to force reload with :call FRRLoadXrefJson()
function! FRRLoadXrefJson() abort
	let s:xrefpath = findfile("frr.xref", ".;")
	if empty(s:xrefpath)
		throw "frr.xref JSON file not found in current or parent directories"
	endif
	let xreflines = readfile(s:xrefpath)
	let s:xrefjson = json_decode(join(xreflines, "\n"))
endfunction

function! FRRXrefJson() abort
	if empty(s:xrefjson)
		call FRRLoadXrefJson()
	endif
	return s:xrefjson
endfunction

function! FRRGotoXref(ident) abort
	let refs = FRRXrefJson()["refs"]
	if has_key(refs, a:ident)
		" TODO: in rare cases, one ID may occur in multiple places.
		" Add some UI for that.  (This happens if the exact same
		" format string is logged in multiple places in the same
		" file.)
		let loc = refs[a:ident][0]
		let basepath = fnamemodify(s:xrefpath, ":p:h")
		let path = fnamemodify(basepath . "/" . loc["file"], ":.")
		execute "e ".fnameescape(path)
		execute ":".loc["line"]
	else
		echoerr printf("cannot find xref with ID %s", a:ident)
	endif
endfunction

" invoke as :GotoXref 23456-ABCDE
command! -bang -nargs=1 GotoXref :call FRRGotoXref(<q-args>)

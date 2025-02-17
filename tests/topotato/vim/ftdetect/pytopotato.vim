function! TopotatoDetect()
	let save_cursor = getcurpos()
	call cursor(1, 1)
	" look for 'import topotato' or 'from topotato' in first 30 lines
	if search('^\s*\(import\|from\)\s\+topotato', "c", 30)
		set filetype=pytopotato
	endif
	call setpos('.', save_cursor)
endfunction

autocmd BufRead,BufNewFile *.py call TopotatoDetect()

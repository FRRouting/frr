function expand_container(obj) {
	while (obj.parentElement && !obj.classList.contains("e_cont"))
		obj = obj.parentElement;
	return obj;
}

function raw_expand(obj, ev) {
	obj = expand_container(obj);

	for (target of obj.getElementsByClassName("e_hide")) {
		var et = expand_container(target.parentElement);
		if (et != obj) {
			console.log("skip expanding", target);
			continue;
		}

		if (target.classList.contains("e_show")) {
			target.classList.remove("e_show");
		} else {
			target.classList.add("e_show");
		}
	}
	ev.stopPropagation();
}

function expandall(obj, evt) {
	obj = expand_container(obj);

	for (target of obj.getElementsByClassName("e_hide")) {
		if (!target.classList.contains("e_show")) {
			target.classList.add("e_show");
		}
	}
	ev.stopPropagation();
}

var mx, my;

function bmdown(evt) {
	mx = evt.x;
	my = evt.y;
}

function hideall(evt) {
	var moved = Math.abs(evt.x - mx, 2) + Math.abs(evt.y - my);
	if (moved > 15)
		return;

	for (target of Array.from(document.getElementsByClassName("e_show"))) {
		target.classList.remove("e_show");
	}
}

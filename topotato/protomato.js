function container_class(obj, classname) {
	while (obj.parentElement && !obj.classList.contains(classname))
		obj = obj.parentElement;
	return obj;
}

function container_tag(obj, tagname) {
	while (obj.parentElement && obj.tagName.toLowerCase() != tagname)
		obj = obj.parentElement;
	return obj;
}

function raw_expand(obj, ev) {
	obj = container_class(obj, "e_cont");

	for (target of obj.getElementsByClassName("e_hide")) {
		var et = container_class(target.parentElement, "e_cont");
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
	if (obj.classList.contains("e_expanded")) {
		obj.classList.remove("e_expanded");
	} else {
		obj.classList.add("e_expanded");
	}
	ev.stopPropagation();
}

function expandall(obj, evt) {
	obj = container_class(obj, "e_cont");

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
	var moved = Math.abs(evt.x - mx) + Math.abs(evt.y - my);
	if (moved > 15)
		return;

	for (target of Array.from(document.getElementsByClassName("e_show"))) {
		target.classList.remove("e_show");
	}
}

var anchor_active = null;
var anchor_current = {};
const anchor_defaults = {
	"log": "ewni"
};

const log_keys = {
	"prio-error": "e",
	"prio-warn": "w",
	"prio-notif": "n",
	"prio-info": "i",
	"prio-debug": "d",
	"prio-startup": "s",
};

function log_show(key, sel) {
	enabled = {}
	if (sel == "-") {
		cbox = document.getElementById("cf-log");
		cbox.checked = false;
		for (const [classname, ctlchar] of Object.entries(log_keys)) {
			cbox = document.getElementById("cf-".concat(classname));
			cbox.disabled = true;
		}
	} else {
		cbox = document.getElementById("cf-log");
		cbox.checked = true;
		for (const [classname, ctlchar] of Object.entries(log_keys)) {
			enabled[classname] = (sel.indexOf(ctlchar) >= 0);

			cbox = document.getElementById("cf-".concat(classname));
			cbox.checked = enabled[classname];
			cbox.disabled = false;
		}
	}

	for (target of Array.from(document.getElementsByClassName("logmsg"))) {
		var enable = false;
		var prio = Array.from(target.classList).filter(s => s.startsWith("prio-"))[0]

		if (prio === undefined)
			prio = "prio-startup";
		if (prio in enabled)
			enable = enabled[prio];
		else
			enable = true;
		if (target.classList.contains("assert-match"))
			enable = true;
		target.style.display = enable ? "contents" : "none";
	}
}

const anchor_funcs = {
	"log": log_show,
};

function anchor_apply(opts) {
	for (const [key, val] of Object.entries(opts)) {
		console.log("apply", key, val, anchor_current[key]);
		if ((key in anchor_current) && (anchor_current[key] === val))
		    continue;

		anchor_funcs[key](key, val);
		anchor_current[key] = val;
	}
}

function anchor_update() {
	var loc = decodeURIComponent(location.hash);

	if (loc.startsWith("#")) {
		loc = loc.substr(1);
	}

	args = loc.split(",");
	anchor = args.shift();

	prev_anchor = anchor_active;
	if (anchor_active !== null) {
		anchor_active.classList.remove("active");
	}
	anchor_active = null;

	if (anchor) {
		anchored = document.getElementById(anchor);
		if (anchored) {
			anchor_active = anchored;
			if (anchored !== prev_anchor)
				anchored.scrollIntoView();
			anchor_active.classList.add("active");
		}
	}

	opts = {...anchor_defaults};
	for (arg of args) {
		s = arg.split("=");
		key = s.shift();
		val = s.join("=");

		if (key in anchor_funcs) {
			opts[key] = val;
		} else {
			console.log("unknown parameter", arg);
		}
	}

	console.log("apply options:", opts);
	anchor_apply(opts);
}

function anchor_export(opts) {
	var out = [];

	if (anchor_active !== null)
		out.push(anchor_active.id);
	else
		out.push("");

	for (const [key, val] of Object.entries(opts)) {
		if ((key in anchor_defaults) && (anchor_defaults[key] === val))
		    continue;

		out.push(key + "=" + val);
	}
	out.push("");

	location.hash = "#".concat(out.join(","));
}

function onclicklog(evt) {
	const srcid = evt.target.id;
	const checked = evt.target.checked;

	opts = {...anchor_current};

	if (srcid == "cf-log" && !checked)
		opts["log"] = "-";
	else {
		var optstr = [];

		for (const [classname, ctlchar] of Object.entries(log_keys)) {
			if (document.getElementById("cf-".concat(classname)).checked)
				optstr.push(ctlchar);
		}
		opts["log"] = optstr.join("");
	}
	anchor_export(opts);
}

function onclickclicmd(evt) {
	evt.stopPropagation();

	pobj = container_class(evt.target, "clicmd");
	obj = pobj.nextElementSibling;
	if (obj.style.display == "contents") {
		pobj.classList.remove("cli-expanded");
		obj.style.display = "none";
	} else {
		pobj.classList.add("cli-expanded");
		obj.style.display = "contents";
	}
}

function onhashchange(evt) {
	anchor_update();
}

var svg_hilight = null;

function onmouseenter_ethsrc(evt) {
	const obj = evt.target;

	if (svg_hilight !== null)
		svg_hilight.classList.remove("src-hilight");
	svg_hilight = null;

	data = evt.target.textContent.match("^([^ ]+) \\((.*)\\)$");
	router = data[1];
	iface = data[2];

	svg_rtr = document.getElementById("router-" + router);
	for (const textobj of svg_rtr.getElementsByTagName("text")) {
		if (textobj.textContent == iface) {
			poly = textobj;
			while (poly.tagName != "polygon")
				poly = poly.previousElementSibling;

			svg_hilight = poly;
			poly.classList.add("src-hilight");
		}
	}
}

function onmouseleave_ethsrc(evt) {
	if (svg_hilight !== null)
		svg_hilight.classList.remove("src-hilight");
	svg_hilight = null;
}

var pdmltree;

function pdml_add_field(htmlparent, field) {
	if (field.attributes["hide"])
		return;

	var htmlfield = document.createElement("div");
	var fdata = document.createElement("span");
	if ("showname" in field.attributes) {
		fdata.textContent = field.attributes["showname"].value;
	} else if ("show" in field.attributes) {
		fdata.textContent = field.attributes["show"].value;
	} else {
		fdata.textContent = "(unnamed)";
	}
	if ("name" in field.attributes && "value" in field.attributes) {
		fdata.title = field.attributes["name"].value + ": " +
			field.attributes["value"].value;
	}
	htmlfield.appendChild(fdata);
	htmlparent.appendChild(htmlfield);

	for (const childfield of field.children)
		pdml_add_field(htmlfield, childfield);
	return htmlfield;
}

function expand_proto(title) {
	var fields = title.nextSibling;

	if (fields.style.display == "none") {	
		fields.style.display = "block";
	} else {
		fields.style.display = "none";
	}
}

function onclick_pdml_dt(evt) {
	expand_proto(container_tag(evt.target, "dt"));
}

function pdml_add_proto(htmlparent, proto) {
	var title = document.createElement("dt");
	if ("showname" in proto.attributes) {
		title.textContent = proto.attributes["showname"].value;
	} else if ("show" in proto.attributes) {
		title.textContent = proto.attributes["show"].value;
	} else {
		title.textContent = "(?)";
	}
	title.onclick = onclick_pdml_dt;
	htmlparent.appendChild(title);

	var fields = document.createElement("dd");
	fields.style.display = "none";
	htmlparent.appendChild(fields);

	for (const field of proto.children)
		pdml_add_field(fields, field);

	return title;
}

function onclick_pkt(evt) {
	const pkt = container_class(evt.target, "pkt");
	const infopane = document.getElementById("infopane");

	pdml_frame = pkt.attributes["pdml_frame"].value;
	lookup = pdmltree.evaluate("packet[proto[@name='geninfo']/field[@name='num'][@show='" + pdml_frame + "']]", pdmltree.children[0], null, XPathResult.UNORDERED_NODE_ITERATOR_TYPE);

	packet = lookup.iterateNext();

	console.log("pkt click:", pkt, pdml_frame, packet);

	htmlpacket = document.createElement("dl");
	htmlpacket.classList.add("pdml-root");

	var last_htmlproto;

	for (const proto of packet.children)
		last_htmlproto = pdml_add_proto(htmlpacket, proto);

	expand_proto(last_htmlproto);
	infopane.replaceChildren(htmlpacket);
}

function b64_inflate_json(b64data) {
	var bytearr = Uint8Array.from(atob(b64data), i => i.charCodeAt(0))
	var text = new TextDecoder().decode(pako.inflate(bytearr));
	return JSON.parse(text);
}

var jsdata;

function init() {
	document.getElementsByTagName("body")[0].onhashchange = onhashchange;

	for (obj of document.getElementsByClassName("p-eth-src")) {
		obj.onmouseenter = onmouseenter_ethsrc;
		obj.onmouseleave = onmouseleave_ethsrc;
	}
	for (obj of document.getElementsByClassName("pkt")) {
		obj.onclick = onclick_pkt;
	}

	jsdata = b64_inflate_json(data);

	var parser = new DOMParser();
	pdmltree = parser.parseFromString(jsdata.pdml, "application/xml");

	anchor_update();
}

function anchorclick(evt) {
	evt.stopPropagation();

	var targetanchor = evt.target.href;
	targetanchor = targetanchor.substr(targetanchor.indexOf("#") + 1);

	if (anchor_active !== null) {
		anchor_active.classList.remove("active");
	}
	anchor_active = null;

	anchored = document.getElementById(targetanchor);
	console.log("anchor-click", targetanchor, anchored);
	if (anchored) {
		anchor_active = anchored;
		if (anchored !== prev_anchor)
			anchored.scrollIntoView();
		anchor_active.classList.add("active");
	}

	anchor_export(anchor_current);
	return false;
}

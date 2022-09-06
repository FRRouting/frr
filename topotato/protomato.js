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
		if (arg === "")
			continue;

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

var pdml_decode;

function onclick_pkt(evt) {
	const pkt = container_class(evt.target, "pkt");
	const infopane = document.getElementById("infopane");
	const packet = pkt.obj.pdml;

	htmlpacket = document.createElement("dl");
	htmlpacket.classList.add("pdml-root");

	back_nav = document.createElement("dt");
	back_nav.classList.add("back-nav");
	back_nav.textContent = "‹ back to network diagram";
	back_nav.onclick = function () {
		pdml_decode.replaceChildren();
		infopane.children[0].style.display = "";
	};
	htmlpacket.appendChild(back_nav);

	var last_htmlproto;

	for (const proto of packet.children)
		last_htmlproto = pdml_add_proto(htmlpacket, proto);

	expand_proto(last_htmlproto);

	infopane.children[0].style.display = "none";
	pdml_decode.replaceChildren(htmlpacket);
	pdml_decode.style.display = "contents";
}

function b64_inflate_json(b64data) {
	var bytearr = Uint8Array.from(atob(b64data), i => i.charCodeAt(0))
	var text = new TextDecoder().decode(pako.inflate(bytearr));
	return JSON.parse(text);
}

/*
 *
 */

var jsdata;
var ts_start;

function create(parent_, tagname, clsname, text = undefined) {
	var element;

	element = document.createElement(tagname);
	for (cls of clsname.split(" "))
		if (cls !== "")
			element.classList.add(cls);
	if (text !== undefined)
		element.appendChild(document.createTextNode(text));
	parent_.appendChild(element);
	return element;
}

function load_log(timetable, obj) {
	var row, logmeta;

	row = create(timetable, "div", "logmsg");
	row.classList.add("prio-" + obj.data.prio);
	row.obj = obj;

	create(row, "span", "tstamp", (obj.ts - ts_start).toFixed(3));
	create(row, "span", "rtrname", obj.data.router);
	create(row, "span", "dmnname", obj.data.daemon);

	logmeta = create(row, "span", "logmeta");
	create(logmeta, "span", "uid", obj.data.uid);

	create(row, "span", "logprio", obj.data.prio);
	create(row, "span", "logtext", obj.data.text.substr(obj.data.arghdrlen));
	/* TODO: obj.data.args */
}

function load_protocols(obj, row, protodefs, protos) {
	while (protos.length > 0) {
		var proto = protos.shift();
		var protoname = proto.getAttribute("name");

		if (!(protoname in protodefs)) {
			console.warn("packet %s: no HTML display for protocol %s", obj.data.frame_num, protoname);
			break;
		}
		if (protodefs[protoname] === null)
			continue;

		try {
			if (protodefs[protoname](obj, row, proto, protos))
				continue;
		} catch (exc) {
			console.warn("packet %s: HTML decode for %s threw exception", obj.data.frame_num, protoname, exc);
		}
		break;
	}
}

function pdml_get(item, key, idx = 0) {
	var iter = pdmltree.evaluate("field[@name='"+key+"']", item, null, XPathResult.ORDERED_NODE_ITERATOR_TYPE);
	var result;

	while (idx >= 0) {
		result = iter.iterateNext();
		if (result === null)
			return null;
		idx--;
	}
	return result;
}

function pdml_get_attr(item, key, attr = "show", idx = 0) {
	var result = pdml_get(item, key, idx);
	return result === null ? null : result.getAttribute(attr);
}

const mld_short_recordtypes = {
	1: "IN",
	2: "EX",
	3: "→IN",
	4: "→EX",
	5: "+S",
	6: "-S",
};

const protocols = {
	"geninfo": null,
	"frame": null,
	"pkt_comment":  function (obj, row, proto, protos) {
		row.classList.add("assert-match");

		var row2 = document.createElement("div");
		row2.classList.add("pkt");
		create(row2, "span", "assert-match-item", pdml_get_attr(proto, "frame.comment"));
		row.after(row2);
		return true;
	},

	"eth": function (obj, row, proto, protos) {
		var col = create(row, "span", "pktcol p-eth");

		create(col, "span", "pktsub p-eth-src", pdml_get_attr(proto, "eth.src"));
		create(col, "span", "pktsub p-eth-arr", "→");
		create(col, "span", "pktsub p-eth-dst", pdml_get_attr(proto, "eth.dst"));
		return true;
	},

	"ip": function (obj, row, proto, protos) {
		create(row, "span", "pktcol l-3 p-ipv4", "IPv4");
		return true;
	},
	"ipv6": function (obj, row, proto, protos) {
		if (pdml_get_attr(proto, "ipv6.src").startsWith("fe80::"))
			create(row, "span", "pktcol l-3 p-ipv6", "IPv6 LL");
		else
			create(row, "span", "pktcol l-3 p-ipv6", "IPv6");
		return true;
	},

	"icmpv6": function (obj, row, proto, protos) {
		pname = "ICMPv6";
		type_num = pdml_get_attr(proto, "icmpv6.type", "show");

		if (["130", "131", "132", "143"].includes(type_num))
			pname = "MLD";

		if (type_num == 143) {
			items = new Array;
			for (record of proto.querySelectorAll("field[name='icmpv6.mldr.mar']")) {
				raddr = pdml_get_attr(record, "icmpv6.mldr.mar.multicast_address");
				rtype = pdml_get_attr(record, "icmpv6.mldr.mar.record_type");
				items.push(mld_short_recordtypes[rtype] + "(" + raddr + ")");
			}
			text = "v2 report: " + items.join(", ");
		} else {
			type = pdml_get_attr(proto, "icmpv6.type", "showname");
			text = type.split(": ").slice(1).join(": ");
		}
		create(row, "span", "pktcol l-4 p-icmpv6", pname);
		create(row, "span", "pktcol l-5 detail last", text);
		return false;
	},
	"udp": function (obj, row, proto, protos) {
		create(row, "span", "pktcol l-4 p-udp last", `UDP ${pdml_get_attr(proto, "udp.srcport")} → ${pdml_get_attr(proto, "udp.dstport")}`);
		return false;
	},
};

function load_packet(timetable, obj, pdmltree) {
	var row, pdml;

	pdml = pdmltree.evaluate(
		"packet[proto[@name='geninfo']/field[@name='num'][@show='" + obj.data.frame_num + "']]",
		pdmltree.children[0], null, XPathResult.ANY_UNORDERED_NODE_TYPE).singleNodeValue;

	if (!pdml) {
		console.error("Could not find frame number %s in PDML", obj.data.frame_num);
		return;
	}
	obj.pdml = pdml;

	row = create(timetable, "div", "pkt");
	row.obj = obj;
	row.onclick = onclick_pkt;

	create(row, "span", "pktcol tstamp", (obj.ts - ts_start).toFixed(3));
	create(row, "span", "pktcol ifname", obj.data.iface);

	load_protocols(obj, row, protocols, Array.from(pdml.children));
}

function init() {
	document.getElementsByTagName("body")[0].onhashchange = onhashchange;

	const infopane = document.getElementById("infopane");
	pdml_decode = create(infopane, "div", "pdml_decode");
	pdml_decode.style.display = "none";

	for (obj of document.getElementsByClassName("p-eth-src")) {
		obj.onmouseenter = onmouseenter_ethsrc;
		obj.onmouseleave = onmouseleave_ethsrc;
	}

	jsdata = b64_inflate_json(data);
	ts_start = jsdata.ts_start;

	var parser = new DOMParser();
	pdmltree = parser.parseFromString(jsdata.pdml, "application/xml");

	var timetable;
	var ts_end = parseFloat('-Infinity');
	var item_idx = -1;

	for (idx in jsdata.timed) {
		var obj = jsdata.timed[idx];
		obj.idx = idx;

		while (obj.ts > ts_end && item_idx < jsdata.items.length) {
			item_idx++;
			ts_end = jsdata.items[item_idx].ts_end;
			timetable = document.getElementById("i" + item_idx + "d").getElementsByClassName("timetable")[0];
		}

		if (obj.data.type == "packet")
			load_packet(timetable, obj, pdmltree);
		else if (obj.data.type == "log")
			load_log(timetable, obj);
	}

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

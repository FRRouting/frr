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

function onmouseenter_eth(evt) {
	const obj = evt.target;

	if (svg_hilight !== null)
		svg_hilight.classList.remove("src-hilight");
	svg_hilight = null;

	svg_rtr = document.getElementById("router-" + obj.d_router);
	for (const textobj of svg_rtr.getElementsByTagName("text")) {
		if (textobj.textContent == obj.d_iface) {
			poly = textobj;
			while (poly.tagName != "polygon")
				poly = poly.previousElementSibling;

			svg_hilight = poly;
			poly.classList.add("src-hilight");
		}
	}
}

function onmouseleave_eth(evt) {
	if (svg_hilight !== null)
		svg_hilight.classList.remove("src-hilight");
	svg_hilight = null;
}

const eth_wellknown = {
	"ff:ff:ff:ff:ff:ff": "bcast",
	"01:80:c2:00:00:0e": "eth-link",
};

const mac_name_re = /^(.*) \((.*)\)$/;

function eth_pretty(htmlparent, csscls, macaddr) {
	var name;

	if (macaddr in jsdata["macmap"]) {
		name = jsdata["macmap"][macaddr];
		m = name.match(mac_name_re);
		if (m) {
			if (m[2].startsWith(m[1]))
				name = m[2];
			elem = create(htmlparent, "span", csscls, name);
			elem.title = macaddr;
			elem.d_router = m[1];
			elem.d_iface = m[2];
			elem.onmouseenter = onmouseenter_eth;
			elem.onmouseleave = onmouseleave_eth;
			return;
		}
	} else if (macaddr in eth_wellknown)
		name = eth_wellknown[macaddr];
	else if (macaddr.startsWith("01:00:5e:"))
		name = "v4mcast";
	else if (macaddr.startsWith("33:33:"))
		name = "v6mcast";
	else
		name = macaddr;

	create(htmlparent, "span", csscls, name);
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

	var pdml_raw_btn = create(title, "span", "pdml-raw", "‹R›");
	var pdml_raw = create(fields, "div", "pdml-raw", proto.outerHTML);

	pdml_raw.style.display = "none";
	pdml_raw_btn.onclick = function(evt) {
		evt.stopPropagation();
		if (pdml_raw.style.display == "none")
			pdml_raw.style.display = "block";
		else
			pdml_raw.style.display = "none";
	}


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

function load_vtysh(timetable, obj) {
	var row;

	row = create(timetable, "div", "clicmd");
	row.obj = obj;

	create(row, "span", "tstamp", (obj.ts - ts_start).toFixed(3));
	create(row, "span", "rtrname", obj.data.router);
	create(row, "span", "dmnname", obj.data.daemon);
	create(row, "span", "clicmdtext", obj.data.command);

	if (obj.data.text) {
		row.classList.add("cli-has-out");
		row.onclick = onclickclicmd;

		var textrow = create(timetable, "div", "cliout");
		create(textrow, "span", "cliouttext", obj.data.text);
	}
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

function strip_colon(text) {
	return text.split(": ").slice(1).join(": ");
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

		eth_pretty(col, "pktsub p-eth-src", pdml_get_attr(proto, "eth.src"));
		create(col, "span", "pktsub p-eth-arr", "→");
		eth_pretty(col, "pktsub p-eth-dst", pdml_get_attr(proto, "eth.dst"));
		return true;
	},

	"arp": function (obj, row, proto, protos) {
		create(row, "span", "pktcol l-3 p-arp last", "ARP");
		return false;
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
		type_num = pdml_get_attr(proto, "icmpv6.type");

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
	"igmp": function (obj, row, proto, protos) {
		type = pdml_get_attr(proto, "igmp.type", "showname");
		text = type.split(": ").slice(1).join(": ");

		create(row, "span", "pktcol l-4 p-igmp", `IGMPv${pdml_get_attr(proto, "igmp.version")}`);
		create(row, "span", "pktcol l-5 detail last", text);
		return false;
	},
	"udp": function (obj, row, proto, protos) {
		create(row, "span", "pktcol l-4 p-udp last", `UDP ${pdml_get_attr(proto, "udp.srcport")} → ${pdml_get_attr(proto, "udp.dstport")}`);
		return false;
	},
	"tcp": function (obj, row, proto, protos) {
		if (proto.nextElementSibling)
			return true;

		elem = create(row, "span", "pktcol l-4 p-tcp last", `TCP ${pdml_get_attr(proto, "tcp.srcport")} → ${pdml_get_attr(proto, "tcp.dstport")}`);
		return false;
	},

	"pim": function (obj, row, proto, protos) {
		type = pdml_get_attr(proto, "pim.type", "showname").split(": ").slice(1).join(": ");
		type_num = pdml_get_attr(proto, "pim.type", "show");

		if (type_num == 3) {
			items = new Array;
			for (group of proto.querySelectorAll("field[name='pim.group_set']")) {
				grptext = pdml_get_attr(group, "pim.group_ip6") || pdml_get_attr(group, "pim.group");
				items.push(grptext);
			}
			text = "J/P: " + items.join(", ");
		} else {
			text = type;
		}
		create(row, "span", "pktcol l-4 p-pim", "PIM");
		create(row, "span", "pktcol l-5 p-pim detail last", text);
		return false;
	},
	"bgp": function (obj, row, proto, protos) {
		const rex = /^.*: (.*?) Message.*/;

		var items = new Array;
		var idx = 0;

		while (proto && idx++ < 6) {
			msgtype = pdml_get_attr(proto, "bgp.type", "showname");
			m = msgtype.match(rex);
			if (!m) {
				items.push(msgtype);
				proto = proto.nextElementSibling;
				continue;
			}

			msgtype = m[1];
			if (msgtype == "NOTIFICATION") {
				major = strip_colon(pdml_get_attr(proto, "bgp.notify.major_error", "showname"));
				minor = strip_colon(proto.lastElementChild.getAttribute("showname"));
				msgtype = `NOTIFY ${major}/${minor}`;
			} else if (msgtype == "UPDATE") {
				subitems = new Array;

				for (nlri of proto.querySelectorAll("field[name='bgp.update.nlri']")) {
					subitems.push(pdml_get_attr(nlri, ""));
				}
				msgtype = "UPDATE [" + subitems.join(", ") + "]";
			}
			items.push(msgtype);
			proto = proto.nextElementSibling;
		}
		create(row, "span", "pktcol l-4 p-bgp", "BGP");
		create(row, "span", "pktcol l-5 p-bgp detail last", items.join(", "));
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

function pullup(arr, item) {
	var pos = arr.indexOf(item);
	if (pos < 0)
		return;
	arr.splice(pos, 1)
	arr.unshift(item)
}

var cfg_selected = null;
var cfg_wrap, cfg_text, cfg_dl;

function cfg_click(evt) {
	evt.stopPropagation();
	var item = evt.target;

	if (cfg_selected !== null)
		cfg_selected.classList.remove("active");

	cfg_selected = item;
	if (cfg_selected === null || item._config === null) {
		cfg_selected = null;
		cfg_wrap.style.display = "none";
		cfg_text.innerText = "";
		cfg_dl.href = "data:";
		return;
	}
	cfg_selected.classList.add("active");
	cfg_wrap.style.display = "block";
	cfg_text.innerText = item._config;
	cfg_dl.download = `${item._router}_${item._daemon}.conf`;
	cfg_dl.href = "data:text/plain;charset=UTF-8," + encodeURIComponent(item._config);
}

function load_configs(configs) {
	var linklist = document.querySelector("div#main > ul");

	var cfg_root = document.createElement("dl");
	cfg_root.classList.add("configs");
	linklist.after(cfg_root);

	cfg_wrap = document.createElement("div");
	cfg_wrap.classList.add("config");
	cfg_wrap.style.display = "none";
	cfg_root.after(cfg_wrap);

	var cfg_buttons = create(cfg_wrap, "div", "cfg-buttons");
	cfg_dl = create(cfg_buttons, "a", "cfg-dl", "▽ download");

	var cfg_close = create(cfg_buttons, "span", "cfg-close", "☒ close");
	cfg_close.clickable = true;
	cfg_close._config = null;
	cfg_close.onclick = cfg_click;

	cfg_text = create(cfg_wrap, "code", "config");

	var daemons = new Array();

	for (var rtr of Object.keys(configs))
		daemons = daemons.concat(Object.keys(configs[rtr]));

	daemons = new Array(...new Set(daemons));
	daemons.sort();
	pullup(daemons, 'staticd');
	pullup(daemons, 'zebra');

	cfg_root.style.gridTemplateColumns = `repeat(${daemons.length + 1}, max-content)`;

	for (var rtr of Object.keys(configs).sort()) {
		create(cfg_root, "dt", "", rtr);

		for (var daemon of daemons) {
			if (daemon in configs[rtr]) {
				var item = create(cfg_root, "dd", "cfg-present", `${daemon}.conf`);
				item.clickable = true;
				item._router = rtr;
				item._daemon = daemon;
				item._config = configs[rtr][daemon];
				item.onclick = cfg_click;
			} else
				create(cfg_root, "dd", "cfg-absent", ``);
		}
	}
}

function init() {
	document.getElementsByTagName("body")[0].onhashchange = onhashchange;

	const infopane = document.getElementById("infopane");
	pdml_decode = create(infopane, "div", "pdml_decode");
	pdml_decode.style.display = "none";

	jsdata = b64_inflate_json(data);
	ts_start = jsdata.ts_start;

	load_configs(jsdata.configs);

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
		else if (obj.data.type == "vtysh")
			load_vtysh(timetable, obj);
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

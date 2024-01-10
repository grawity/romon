rdata_protocol = Proto("romondata", "RoMON data")

local f_type_names = {
	[0] = "Connect(syn)?",
	[1] = "Accept?",
	[2] = "Data?",
	[3] = "Ack?",
	[4] = "Close?",
}

f_srcport = ProtoField.uint16("romondata.srcport", "Source port", base.DEC)
f_dstport = ProtoField.uint16("romondata.dstport", "Destination port", base.DEC)
f_type = ProtoField.uint8("romondata.type", "Type", base.DEC, f_type_names)
f_unk2 = ProtoField.uint8("romondata.unk2", "Unknown", base.DEC)
f_seq = ProtoField.uint32("romondata.seq", "Sequence")
f_ack = ProtoField.uint32("romondata.ack", "Acknowledge")

rdata_protocol.fields = {
	f_srcport,
	f_dstport,
	f_type,
	f_unk2,
	f_seq,
	f_ack,
}

subdis = DissectorTable.new("RoMONdata")
subdis:add(1, Dissector.get("data"))
subdis:add(3, Dissector.get("ssh"))
--subdis:add(4, Dissector.get("winbox"))

function rdata_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = rdata_protocol.name

	local subtree = tree:add(rdata_protocol, buffer(), "Mikrotik RoMON data")

	subtree:add(f_srcport, buffer(0, 2))
	subtree:add(f_dstport, buffer(2, 2))

	local srcport = buffer(0, 2):uint()
	local dstport = buffer(2, 2):uint()
	pinfo.src_port = srcport
	pinfo.dst_port = dstport
	--subtree:append_text(", Src: " .. srcport)
	--subtree:append_text(", Dst: " .. dstport)
	--pinfo.cols.info.set("Data (" .. srcport .. " -> " .. dstport .. ")")

	subtree:add(f_type, buffer(4, 1))
	subtree:add(f_unk2, buffer(5, 1))
	subtree:add(f_seq, buffer(6, 4))
	subtree:add(f_ack, buffer(10, 4))

	if srcport == 3 or dstport == 3 or srcport == 4 or dstport == 4 then
		local rest = buffer(14):tvb()
		if rest:len() > 0 then
			subdis:try(srcport, rest, pinfo, tree)
			subdis:try(dstport, rest, pinfo, tree)
			--Dissector.get("data"):call(rest, pinfo, tree)
		end
	else
		local rest = buffer(4):tvb()
		Dissector.get("data"):call(rest, pinfo, tree)
	end
end

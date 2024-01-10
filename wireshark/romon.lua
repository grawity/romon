-- ~/.local/lib/wireshark/plugins/romon.lua

romon_protocol = Proto("RoMON", "Mikrotik RoMON Protocol")

local f_type_names = {
	[1] = "Discover",
	[2] = "DiscoverResp",
	[3] = "Data",
	[4] = "SeqErr",
	[5] = "Hello",
}

f_type = ProtoField.uint8("romon.type", "Type", base.DEC, f_type_names)
f_unk1 = ProtoField.uint8("romon.unk1", "Unknown", base.HEX)
f_length = ProtoField.uint16("romon.l2length", "Length", base.DEC)
f_unk2 = ProtoField.bytes("romon.unk2", "Unknown (HMAC?)")
f_srcaddr = ProtoField.ether("romon.src", "Source", "Source RoMON ID")
f_dstaddr = ProtoField.ether("romon.dst", "Destination", "Destination RoMON ID")

f_num_links = ProtoField.uint8("romon.num_links", "Links", base.DEC)
f_link_ptr = ProtoField.uint8("romon.link_ptr", "Current link", base.DEC)
f_unk3 = ProtoField.bytes("romon.unk3", "Unknown")
f_unk4 = ProtoField.bytes("romon.unk3", "Unknown")

f_link = ProtoField.none("romon.path", "Path")
f_link_maybeid = ProtoField.uint32("romon.path.link_maybeid", "Link ID?", base.DEC)
f_link_mac = ProtoField.ether("romon.path.link_mac", "Link MAC?")

romon_protocol.fields = {
	f_type,
	f_unk1,
	f_length,
	f_unk2,
	f_srcaddr,
	f_dstaddr,

	f_num_links,
	f_link_ptr,
	f_unk3,
	f_unk4,

	f_link,
	f_link_maybeid,
	f_link_mac,
}

function romon_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = romon_protocol.name

	--length = buffer:len()

	local subtree = tree:add(romon_protocol, buffer(), "Mikrotik RoMON")

	subtree:add(f_type, buffer(0, 1))
	subtree:add(f_unk1, buffer(1, 1))
	subtree:add(f_length, buffer(2, 2))
	subtree:add(f_unk2, buffer(4, 24))
	subtree:add(f_srcaddr, buffer(28, 6))
	subtree:add(f_dstaddr, buffer(34, 6))

	local pkt_type = buffer(0, 1):uint()
	local src_addr = buffer(28, 6)
	local dst_addr = buffer(34, 6)
	pinfo.src = src_addr:ether()
	pinfo.dst = dst_addr:ether()
	subtree:append_text(", Src: " .. src_addr)
	subtree:append_text(", Dst: " .. dst_addr)
	--pinfo.cols.info.set(src_addr .. " -> " .. dst_addr)
	
	-- Source route (identical between 1/2, similar in 3)
	if pkt_type == 1 or pkt_type == 2 or pkt_type == 3 then
		local buf = nil
		subtree:add(f_num_links, buffer(40, 1))
		subtree:add(f_link_ptr, buffer(41, 1))
		if pkt_type <= 2 then
			subtree:add(f_unk3, buffer(42, 2))
			subtree:add(f_unk4, buffer(44, 4))
			buf = buffer(48):tvb()
		else
			subtree:add(f_unk4, buffer(42, 4))
			buf = buffer(46):tvb()
		end

		local num_links = buffer(40, 1):uint()
		local link_ptr = buffer(41, 1):uint()
		for i = 1, num_links do
			local row = subtree:add(f_link)
			row:add(f_link_maybeid, buf(0, 4))
			row:add(f_link_mac, buf(4, 6))
			row:append_text(": " .. buf(0, 4):uint())
			row:append_text(" / " .. buf(4, 6))
			if i == link_ptr then
				row:append_text(" <--")
			end
			buf = buf(10):tvb()
		end
		buffer = buf
	else
		buffer = buf(40):tvb()
	end

	-- Payload
	if pkt_type == 1 or pkt_type == 2 then
		Dissector.get("romondisco"):call(buffer, pinfo, tree)
	elseif pkt_type == 3 then
		Dissector.get("romondata"):call(buffer, pinfo, tree)
	else
		Dissector.get("data"):call(buffer, pinfo, tree)
	end
end

local etype_encap_table = DissectorTable.get("ethertype")
etype_encap_table:add(0x88bf, romon_protocol)

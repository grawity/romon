rdisco_protocol = Proto("romondisco", "RoMON discovery")

local f_tag_names = {
	[1] = "Route",
	[3] = "Identity",
	[4] = "Version",
	[5] = "Board",
}

f_tag = ProtoField.uint8("romon.disco.tag", "Tag", base.DEC, f_tag_names)
f_len = ProtoField.uint8("romon.disco.len", "Length", base.DEC)
f_strval = ProtoField.string("romon.disco.str", "Value")
f_binval = ProtoField.bytes("romon.disco.bin", "Value")
f_addr = ProtoField.bytes("romon.disco.id", "RoMON ID")

f_link = ProtoField.none("romon.disco.link", "Link")
f_link_maybeid = ProtoField.uint32("romon.disco.link_maybeid", "Link ID?", base.DEC)
f_link_unk1 = ProtoField.uint16("romon.disco.link_unk1", "Unknown", base.DEC)
f_link_cost = ProtoField.uint16("romon.disco.link_cost", "Cost", base.DEC)
f_link_mac = ProtoField.ether("romon.disco.link_mac", "Link MAC?")

rdisco_protocol.fields = {
	f_tag,
	f_len,
	f_strval,
	f_binval,
	f_addr,
	f_link,
	f_link_maybeid,
	f_link_unk1,
	f_link_cost,
	f_link_mac,
}

function rdisco_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = rdisco_protocol.name

	local subtree = tree:add(rdisco_protocol, buffer(), "Mikrotik RoMON discovery")
	local length = buffer:len()
	while length > 0 do
		local tag = buffer(0, 1):uint()
		local len = buffer(1, 1):uint()

		local tlv = subtree:add(f_tag, buffer(0, 1))
		tlv:add(f_len, buffer(1, 1))
		if tag == 1 then
			-- routing
			tlv:add(f_addr, buffer(2, 6))
			for i = 0, 1 do
				local buf = buffer(8 + (i * 14)):tvb()
				local row = tlv:add(f_link)
				row:add(f_link_maybeid, buf(0, 4))
				row:add(f_link_unk1, buf(4, 2))
				row:add(f_link_cost, buf(6, 2))
				row:add(f_link_mac, buf(8, 6))
				row:append_text(": " .. buf(0, 4):uint())
				row:append_text(" / " .. buf(8, 6))
				row:append_text(", Unk: " .. buf(4, 2):uint())
				row:append_text(", Cost: " .. buf(6, 2):uint())
			end
		elseif tag == 3 or tag == 5 then
			tlv:add(f_strval, buffer(2, len))
		else
			tlv:add(f_binval, buffer(2, len))
		end

		buffer = buffer(len + 2):tvb()
		length = length - (len + 2)
	end
end

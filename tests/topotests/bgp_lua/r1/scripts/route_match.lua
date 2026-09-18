-- BGP route-map match script for the bgp_lua topotest.
--
-- route_match arguments:
--   table prefix
--   table attributes
--   table peer
--   integer RM_FAILURE / RM_NOMATCH / RM_MATCH / RM_MATCH_AND_CHANGE
--   table path

function route_match(prefix, attributes, peer,
		RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE, path)

	log.info("Evaluating " .. prefix.network ..
		 " from AS " .. tostring(peer.remote_as))

	-- Peer context must be populated for every evaluation.
	if not peer or peer.remote_as ~= 65002 then
		log.info("No match: unexpected peer")
		return { action = RM_NOMATCH }
	end

	if prefix.network == "10.0.1.0/24" then
		return { action = RM_MATCH }
	end

	if prefix.network == "10.0.2.0/24" then
		return { action = RM_NOMATCH }
	end

	if prefix.network == "10.0.3.0/24" then
		attributes.metric = 123
		return {
			action = RM_MATCH_AND_CHANGE,
			attributes = attributes
		}
	end

	if prefix.network == "10.0.4.0/24" then
		attributes.community = "65001:1"
		attributes.localpref = 200
		attributes.weight = 400
		return {
			action = RM_MATCH_AND_CHANGE,
			attributes = attributes
		}
	end

	-- 10.0.5.0/24 is tagged 65002:99 by r2; 10.0.6.0/24 is not.
	if attributes.community
			and string.find(attributes.community, "65002:99", 1, true) then
		return { action = RM_MATCH }
	end

	return { action = RM_NOMATCH }
end

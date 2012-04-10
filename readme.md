
# NOTE OF WARNING - WIP 
AS-IS this was a working proof-of-concept only, that failed on 
many layers, global resource control, persistant data 
(initially records were deleted), data growth (fixed), and
the ability to intergrate into an existing auth system (never finished)  

Combining Actions and Resources had its draw-backs, for example, 
not being able to deny everything for a resource.

As such work continues on this to make it something that could be
useful, both standalone and intergrated into an existing auth system.

# Doorway - A Smaller, Simpler ACL library

Simplifies ACL by integrating a couple key componets into the 
permission layer(actions and resources), and applying
a DENY ALL as the default. 

# PURPOSE

Doorway aims to be just that -- a doorway into a creating a 
Role-Based Access Control system (RBAC).  Its up to you, 
the future developer to go forth and fork doorway to meet 
your meet your specific business access needs.

# USAGE

	//create an access object
	$access = new Doorway($pdo);

	//create a new member
	$member_id  = $access>create_member('Geoff Doty', 'Developer');

	//create new group
	$group_id   = $access->create_group('Foo', 'Foo Group');

	//setup membership 
	$membership = $access->add_membership($member_id, $group_id);

	//add permission to group
	$permission = $access->create_group_permission($group_id, 'secret', 'read');

	//check if authorized
	if($access->is_authorized( $member_id, 'secret', 'read'))
	{
	    echo 'I CAN tell you the secret -- DOORWAY.';
	}
	else
	{
	    echo 'Nope, I CANNOT tell you the secret';
	}

# NOTES

- DENY by default, if it doesn't exist OR not enabled, you don't have access
- Tokens: resource & action are ALWAYS evaluated as lowercase (case-insensitive)

# TODO

- Add pdo construct, thinking construct($dsn, $user, $pass)
- Evaulate removing description (barebones only?)
- more I am sure...
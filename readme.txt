For StatusBot -

This is just a simple A2S Ping tool, it does not hook into the server whatsoever. This means that it will report as offline when steam is down (but has a 3 minute retry count before notification)

1. The port for the server should be the query port, not the game port. it will complain if it's wrong.
2. The master webhook / downtime ping ID is in the script itself (at the top), for individual webhooks/downtime ping IDs; those can be configured in the servers.json (with the guide below)
3. The Discord ID required you can get by enabling Developer Mode (Settings > Advanced > Developer Mode > Right click on your user > Copy User ID)


The relevant files should generate on first run, I didn't document everything because I suck.

For Servers.json

 ------------------------------------------------------------------------------------------------------
| Field         | Required 	| Description                                                              |
| ------------- | --------  | ------------------------------------------------------------------------ |
| `name`        | ✅       	| Display name for the server.                                             |
| `ip`          | ✅       	| Server IP address.                                                       |
| `port`        | ✅       	| Query port (usually Steam query port, not game port).                    |
| `group`       | ❌       	| Optional group name (used for separate grouped messages).                |
| `restart`     | ❌       	| If true, shows restart schedule in user’s local timezone.                |
| `timezone`    | ❌       	| Used for restart time (e.g., `"America/Edmonton"`).                      |
| `emoji`       | ❌       	| Replaces icon with a simple emoji (e.g., `"🧙"`).                		   |
| `icon_url`    | ❌       	| URL to an image thumbnail (overrides `emoji`).                           |
| `webhook_url` | ❌       	| Optional override for sending updates to a different webhook per server. |
| `ping_id`     | ❌       	| Optional override for pinging a specific user when the server goes down. |
 ------------------------------------------------------------------------------------------------------

Example Multi Server Setup for Servers.json

[
  {
    "name": "Server 1",
    "ip": "IP Here",
    "port": 27016,
    "group": "Mirage: Arcane Warfare",
    "restart": true,
    "timezone": "America/Edmonton",
    "emoji": "🧙",
    "ping_id": "<@123456789012345678>"
  },
  {
    "name": "Server 2",
    "ip": "IP Here",
    "port": 27015,
    "group": "Chivalry: Medieval Warfare",
    "restart": false,
    "timezone": "America/Edmonton",
    "emoji": "⚔️",
    "ping_id": "<@123456789012345678>"
  },
  {
    "name": "Server 3",
    "ip": "IP Here",
    "port": 27017,
    "group": "Chivalry: Deadliest Warrior",
    "restart": false,
    "timezone": "America/Edmonton",
    "emoji": "⚔️",
    "ping_id": "<@123456789012345678>"
  }
]
import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IHttpRequestMethods,
	IDataObject,
	NodeApiError,
	JsonObject,
} from 'n8n-workflow';

export class SentinelOne implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'SentinelOne',
		name: 'sentinelOne',
		icon: 'file:sentinelone.png',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["resource"] + ": " + $parameter["operation"]}}',
		description: 'Interact with SentinelOne API',
		defaults: {
			name: 'SentinelOne',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'sentinelOneApi',
				required: true,
			},
		],
		properties: [
			// ============================================
			//              RESOURCE SELECTOR
			// ============================================
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'Activity', value: 'activity' },
					{ name: 'Agent', value: 'agent' },
					{ name: 'Device Control', value: 'deviceControl' },
					{ name: 'Exclusion', value: 'exclusion' },
					{ name: 'Group', value: 'group' },
					{ name: 'Hash', value: 'hash' },
					{ name: 'Site', value: 'site' },
					{ name: 'Tag', value: 'tag' },
					{ name: 'Threat', value: 'threat' },
				],
				default: 'agent',
			},

			// ============================================
			//              ACTIVITY OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['activity'] } },
				options: [
					{
						name: 'Get Activities',
						value: 'getActivities',
						description: 'Get activities/audit log entries',
						action: 'Get activities',
					},
					{
						name: 'Get Activity Types',
						value: 'getActivityTypes',
						description: 'Get list of activity types for filtering',
						action: 'Get activity types',
					},
				],
				default: 'getActivities',
			},

			// ============================================
			//              AGENT OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['agent'] } },
				options: [
					{
						name: 'Abort Scan',
						value: 'abortScan',
						description: 'Abort a running scan on agents',
						action: 'Abort scan',
					},
					{
						name: 'Connect to Network',
						value: 'connect',
						description: 'Reconnect agents to the network after isolation',
						action: 'Connect agents to network',
					},
					{
						name: 'Decommission',
						value: 'decommission',
						description: 'Decommission agents (remove from console)',
						action: 'Decommission agents',
					},
					{
						name: 'Disable Agent',
						value: 'disableAgent',
						description: 'Disable protection on agents',
						action: 'Disable agents',
					},
					{
						name: 'Disconnect from Network',
						value: 'disconnect',
						description: 'Isolate (quarantine) agents from the network',
						action: 'Disconnect agents from network',
					},
					{
						name: 'Enable Agent',
						value: 'enableAgent',
						description: 'Enable protection on agents',
						action: 'Enable agents',
					},
					{
						name: 'Fetch Logs',
						value: 'fetchLogs',
						description: 'Request agents to upload logs',
						action: 'Fetch agent logs',
					},
					{
						name: 'Get Agents',
						value: 'getAgents',
						description: 'Get the Agents and their data that match the filter',
						action: 'Get agents',
					},
					{
						name: 'Get Applications',
						value: 'getApplications',
						description: 'Get the installed applications for specific Agents',
						action: 'Get installed applications',
					},
					{
						name: 'Get Passphrase',
						value: 'getPassphrase',
						description: 'Get the passphrase for specific agents',
						action: 'Get agent passphrase',
					},
					{
						name: 'Initiate Scan',
						value: 'initiateScan',
						description: 'Run a Full Disk Scan on Agents that match the filter',
						action: 'Initiate full disk scan',
					},
					{
						name: 'Move to Site',
						value: 'moveToSite',
						description: 'Move agents to a different site',
						action: 'Move agents to site',
					},
					{
						name: 'Restart Machine',
						value: 'restart',
						description: 'Restart endpoints that have an Agent installed',
						action: 'Restart machines',
					},
					{
						name: 'Shutdown',
						value: 'shutdown',
						description: 'Shut down endpoints remotely',
						action: 'Shutdown machines',
					},
					{
						name: 'Uninstall Agent',
						value: 'uninstall',
						description: 'Uninstall Agents from endpoints',
						action: 'Uninstall agents',
					},
					{
						name: 'Update Software',
						value: 'updateSoftware',
						description: 'Initiate agent software update',
						action: 'Update agent software',
					},
				],
				default: 'getAgents',
			},

			// ============================================
			//              THREAT OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['threat'] } },
				options: [
					{
						name: 'Get Threats',
						value: 'getThreats',
						description: 'Get data of threats that match the filter',
						action: 'Get threats',
					},
					{
						name: 'Mitigate Threat',
						value: 'mitigateThreat',
						description: 'Apply a mitigation action to threats',
						action: 'Mitigate threats',
					},
				],
				default: 'getThreats',
			},

			// ============================================
			//           DEVICE CONTROL OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['deviceControl'] } },
				options: [
					{
						name: 'Create Rule',
						value: 'createRule',
						description: 'Create a new Device Control rule',
						action: 'Create device control rule',
					},
					{
						name: 'Delete Rules',
						value: 'deleteRules',
						description: 'Delete Device Control rules',
						action: 'Delete device control rules',
					},
					{
						name: 'Get Device Events',
						value: 'getDeviceEvents',
						description: 'Get Device Control events',
						action: 'Get device control events',
					},
					{
						name: 'Get Device Rules',
						value: 'getDeviceRules',
						description: 'Get the Device Control rules that match the filter',
						action: 'Get device control rules',
					},
					{
						name: 'Update Rule',
						value: 'updateRule',
						description: 'Update an existing Device Control rule',
						action: 'Update device control rule',
					},
				],
				default: 'getDeviceRules',
			},

			// ============================================
			//              EXCLUSION OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['exclusion'] } },
				options: [
					{
						name: 'Create Exclusion',
						value: 'createExclusion',
						description: 'Create a new exclusion (whitelist) entry',
						action: 'Create exclusion',
					},
					{
						name: 'Delete Exclusions',
						value: 'deleteExclusions',
						description: 'Delete exclusion entries',
						action: 'Delete exclusions',
					},
					{
						name: 'Get Exclusions',
						value: 'getExclusions',
						description: 'Get exclusions that match the filter',
						action: 'Get exclusions',
					},
					{
						name: 'Update Exclusion',
						value: 'updateExclusion',
						description: 'Update an existing exclusion entry',
						action: 'Update exclusion',
					},
				],
				default: 'getExclusions',
			},

			// ============================================
			//              GROUP OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['group'] } },
				options: [
					{
						name: 'Get Groups',
						value: 'getGroups',
						description: 'Get groups that match the filter',
						action: 'Get groups',
					},
					{
						name: 'Move Agents',
						value: 'moveAgents',
						description: 'Move agents to a specific group',
						action: 'Move agents to group',
					},
				],
				default: 'getGroups',
			},

			// ============================================
			//              HASH OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['hash'] } },
				options: [
					{
						name: 'Get Verdict',
						value: 'getVerdict',
						description: 'Get the reputation/verdict for a hash',
						action: 'Get hash verdict',
					},
				],
				default: 'getVerdict',
			},

			// ============================================
			//              SITE OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['site'] } },
				options: [
					{
						name: 'Get Sites',
						value: 'getSites',
						description: 'Get sites that match the filter',
						action: 'Get sites',
					},
				],
				default: 'getSites',
			},

			// ============================================
			//              TAG OPERATIONS
			// ============================================
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['tag'] } },
				options: [
					{
						name: 'Get Tags',
						value: 'getTags',
						description: 'Get endpoint tags that match the filters',
						action: 'Get endpoint tags',
					},
					{
						name: 'Manage Tags',
						value: 'manageTags',
						description: 'Add, remove, or override tags on agents',
						action: 'Manage agent tags',
					},
				],
				default: 'getTags',
			},

			// ============================================
			//         GET AGENTS OPTIONS
			// ============================================
			{
				displayName: 'Return All',
				name: 'returnAll',
				type: 'boolean',
				displayOptions: {
					show: {
						resource: ['activity', 'agent', 'threat', 'deviceControl', 'exclusion', 'group', 'site', 'tag'],
						operation: ['getActivities', 'getAgents', 'getThreats', 'getDeviceRules', 'getDeviceEvents', 'getExclusions', 'getGroups', 'getSites', 'getTags'],
					},
				},
				default: false,
				description: 'Whether to return all results or only up to a given limit',
			},
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['activity', 'agent', 'threat', 'deviceControl', 'exclusion', 'group', 'site', 'tag'],
						operation: ['getActivities', 'getAgents', 'getThreats', 'getDeviceRules', 'getDeviceEvents', 'getExclusions', 'getGroups', 'getSites', 'getTags'],
						returnAll: [false],
					},
				},
				typeOptions: { minValue: 1, maxValue: 1000 },
				default: 50,
				description: 'Max number of results to return',
			},

			// Agent Filters
			{
				displayName: 'Filters',
				name: 'filters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['agent'], operation: ['getAgents'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs to filter by (comma-separated)' },
					{ displayName: 'Agent Versions', name: 'agentVersions', type: 'string', default: '', description: 'Agent versions to include (comma-separated)' },
					{ displayName: 'Computer Name Contains', name: 'computerName__contains', type: 'string', default: '', description: 'Free-text filter by computer name' },
					{ displayName: 'Count Only', name: 'countOnly', type: 'boolean', default: false, description: 'Whether to return only the total count' },
					{ displayName: 'Domains', name: 'domains', type: 'string', default: '', description: 'Included network domains (comma-separated)' },
					{ displayName: 'External IP Contains', name: 'externalIp__contains', type: 'string', default: '', description: 'Free-text filter by visible IP' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs to filter by (comma-separated)' },
					{ displayName: 'Infected', name: 'infected', type: 'boolean', default: false, description: 'Whether to include only Agents with active threats' },
					{ displayName: 'Is Active', name: 'isActive', type: 'boolean', default: false, description: 'Whether to include only active Agents' },
					{ displayName: 'Is Pending Uninstall', name: 'isPendingUninstall', type: 'boolean', default: false, description: 'Whether to include only Agents with pending uninstall' },
					{ displayName: 'Is Up To Date', name: 'isUpToDate', type: 'boolean', default: false, description: 'Whether to include only Agents with updated software' },
					{ displayName: 'Last Active Date Between', name: 'lastActiveDate__between', type: 'string', default: '', description: 'Date range (format: from_timestamp-to_timestamp)' },
					{ displayName: 'Last Logged In Username Contains', name: 'lastLoggedInUserName__contains', type: 'string', default: '', description: 'Free-text filter by username' },
					{
						displayName: 'Machine Types', name: 'machineTypes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Desktop', value: 'desktop' }, { name: 'ECS Task', value: 'ecs task' },
							{ name: 'Kubernetes Helper', value: 'kubernetes helper' }, { name: 'Kubernetes Node', value: 'kubernetes node' },
							{ name: 'Kubernetes Pod', value: 'kubernetes pod' }, { name: 'Laptop', value: 'laptop' },
							{ name: 'Server', value: 'server' }, { name: 'Storage', value: 'storage' }, { name: 'Unknown', value: 'unknown' },
						],
					},
					{
						displayName: 'Network Statuses', name: 'networkStatuses', type: 'multiOptions', default: [],
						options: [
							{ name: 'Connected', value: 'connected' }, { name: 'Connecting', value: 'connecting' },
							{ name: 'Disconnected', value: 'disconnected' }, { name: 'Disconnecting', value: 'disconnecting' },
						],
					},
					{
						displayName: 'OS Types', name: 'osTypes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Linux', value: 'linux' }, { name: 'macOS', value: 'macos' },
							{ name: 'Windows', value: 'windows' }, { name: 'Windows Legacy', value: 'windows_legacy' },
						],
					},
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Registered At Between', name: 'registeredAt__between', type: 'string', default: '', description: 'Date range (format: from_timestamp-to_timestamp)' },
					{
						displayName: 'Scan Statuses', name: 'scanStatuses', type: 'multiOptions', default: [],
						options: [
							{ name: 'Aborted', value: 'aborted' }, { name: 'Finished', value: 'finished' },
							{ name: 'None', value: 'none' }, { name: 'Started', value: 'started' },
						],
					},
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs to filter by (comma-separated)' },
					{
						displayName: 'Sort By', name: 'sortBy', type: 'options', default: 'createdAt',
						options: [
							{ name: 'Account Name', value: 'accountName' }, { name: 'Active Threats', value: 'activeThreats' },
							{ name: 'Agent Version', value: 'agentVersion' }, { name: 'Computer Name', value: 'computerName' },
							{ name: 'Created At', value: 'createdAt' }, { name: 'Domain', value: 'domain' },
							{ name: 'External IP', value: 'externalIp' }, { name: 'Group ID', value: 'groupId' },
							{ name: 'ID', value: 'id' }, { name: 'Is Active', value: 'isActive' },
							{ name: 'Last Active Date', value: 'lastActiveDate' }, { name: 'Machine Type', value: 'machineType' },
							{ name: 'Network Status', value: 'networkStatus' }, { name: 'OS Type', value: 'osType' },
							{ name: 'Registered At', value: 'registeredAt' }, { name: 'Site Name', value: 'siteName' },
							{ name: 'Updated At', value: 'updatedAt' },
						],
					},
					{
						displayName: 'Sort Order', name: 'sortOrder', type: 'options', default: 'asc',
						options: [{ name: 'Ascending', value: 'asc' }, { name: 'Descending', value: 'desc' }],
					},
					{ displayName: 'UUID', name: 'uuid', type: 'string', default: '', description: 'Agent UUID' },
					{ displayName: 'UUIDs', name: 'uuids', type: 'string', default: '', description: 'List of Agent UUIDs (comma-separated)' },
				],
			},

			// ============================================
			//         GET APPLICATIONS OPTIONS
			// ============================================
			{
				displayName: 'Agent IDs',
				name: 'agentIds',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['agent'], operation: ['getApplications'] } },
				default: '',
				description: 'Agent ID list (comma-separated)',
			},

			// ============================================
			//         AGENT ACTIONS - TARGET SELECTION
			// ============================================
			{
				displayName: 'Target By',
				name: 'targetBy',
				type: 'options',
				displayOptions: {
					show: {
						resource: ['agent'],
						operation: ['abortScan', 'initiateScan', 'connect', 'disconnect', 'decommission', 'disableAgent', 'enableAgent', 'fetchLogs', 'moveToSite', 'restart', 'shutdown', 'uninstall', 'updateSoftware'],
					},
				},
				options: [
					{ name: 'Agent IDs', value: 'ids', description: 'Target specific agents by their IDs' },
					{ name: 'Filter', value: 'filter', description: 'Target agents matching filter criteria' },
				],
				default: 'ids',
			},
			{
				displayName: 'Agent IDs',
				name: 'actionAgentIds',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['agent'],
						operation: ['abortScan', 'initiateScan', 'connect', 'disconnect', 'decommission', 'disableAgent', 'enableAgent', 'fetchLogs', 'moveToSite', 'restart', 'shutdown', 'uninstall', 'updateSoftware'],
						targetBy: ['ids'],
					},
				},
				default: '',
				description: 'Agent ID list (comma-separated)',
			},
			{
				displayName: 'Action Filters',
				name: 'actionFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: {
					show: {
						resource: ['agent'],
						operation: ['abortScan', 'initiateScan', 'connect', 'disconnect', 'decommission', 'disableAgent', 'enableAgent', 'fetchLogs', 'moveToSite', 'restart', 'shutdown', 'uninstall', 'updateSoftware'],
						targetBy: ['filter'],
					},
				},
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Computer Name Contains', name: 'computerName__contains', type: 'string', default: '', description: 'Free-text filter by computer name' },
					{ displayName: 'Domains', name: 'domains', type: 'string', default: '', description: 'Included network domains (comma-separated)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'Infected', name: 'infected', type: 'boolean', default: false, description: 'Whether to target only infected Agents' },
					{ displayName: 'Is Active', name: 'isActive', type: 'boolean', default: false, description: 'Whether to target only active Agents' },
					{
						displayName: 'Machine Types', name: 'machineTypes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Desktop', value: 'desktop' }, { name: 'Laptop', value: 'laptop' },
							{ name: 'Server', value: 'server' }, { name: 'Kubernetes Node', value: 'kubernetes node' }, { name: 'Unknown', value: 'unknown' },
						],
					},
					{
						displayName: 'Network Statuses', name: 'networkStatuses', type: 'multiOptions', default: [],
						options: [{ name: 'Connected', value: 'connected' }, { name: 'Disconnected', value: 'disconnected' }],
					},
					{
						displayName: 'OS Types', name: 'osTypes', type: 'multiOptions', default: [],
						options: [{ name: 'Linux', value: 'linux' }, { name: 'macOS', value: 'macos' }, { name: 'Windows', value: 'windows' }],
					},
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{ displayName: 'UUIDs', name: 'uuids', type: 'string', default: '', description: 'List of Agent UUIDs (comma-separated)' },
				],
			},

			// ============================================
			//         THREAT OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'threatFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['threat'], operation: ['getThreats'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Agent IDs', name: 'agentIds', type: 'string', default: '', description: 'List of Agent IDs (comma-separated)' },
					{ displayName: 'Agent Is Active', name: 'agentIsActive', type: 'boolean', default: false, description: 'Whether the agent is active' },
					{
						displayName: 'Analyst Verdicts', name: 'analystVerdicts', type: 'multiOptions', default: [],
						options: [
							{ name: 'False Positive', value: 'false_positive' }, { name: 'Suspicious', value: 'suspicious' },
							{ name: 'True Positive', value: 'true_positive' }, { name: 'Undefined', value: 'undefined' },
						],
					},
					{ displayName: 'Classification', name: 'classifications', type: 'string', default: '', description: 'Classification types (comma-separated)' },
					{ displayName: 'Computer Name Contains', name: 'computerName__contains', type: 'string', default: '', description: 'Free-text filter by computer name' },
					{ displayName: 'Content Hash', name: 'contentHashes', type: 'string', default: '', description: 'Content hashes (comma-separated)' },
					{ displayName: 'Created At Between', name: 'createdAt__between', type: 'string', default: '', description: 'Date range (format: from_timestamp-to_timestamp)' },
					{
						displayName: 'Created At - Quick Range',
						name: 'createdAt__quickRange',
						type: 'options',
						default: 'none',
						description: 'Quickly filter threats by creation time. If "Created At (After)" is also set, it takes precedence.',
						options: [
							{ name: 'No Filter', value: 'none' },
							{ name: 'Last 24 Hours', value: 'last24h' },
							{ name: 'Last 7 Days', value: 'last7d' },
							{ name: 'Last 14 Days', value: 'last14d' },
							{ name: 'Last 30 Days', value: 'last30d' },
							{ name: 'Last 90 Days', value: 'last90d' },
						],
					},
					{ displayName: 'Created At (After)', name: 'createdAt__gte', type: 'dateTime', default: '', description: 'Return threats created at or after this date/time' },
					{ displayName: 'Created At (Before)', name: 'createdAt__lte', type: 'dateTime', default: '', description: 'Return threats created at or before this date/time' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{
						displayName: 'Incident Statuses', name: 'incidentStatuses', type: 'multiOptions', default: [],
						options: [
							{ name: 'In Progress', value: 'in_progress' }, { name: 'Resolved', value: 'resolved' }, { name: 'Unresolved', value: 'unresolved' },
						],
					},
					{
						displayName: 'Mitigation Statuses', name: 'mitigationStatuses', type: 'multiOptions', default: [],
						options: [
							{ name: 'Mitigated', value: 'mitigated' }, { name: 'Active', value: 'active' },
							{ name: 'Blocked', value: 'blocked' }, { name: 'Suspicious', value: 'suspicious' },
							{ name: 'Pending', value: 'pending' }, { name: 'Suspicious Resolved', value: 'suspicious_resolved' },
						],
					},
					{
						displayName: 'OS Types', name: 'osTypes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Linux', value: 'linux' }, { name: 'macOS', value: 'macos' },
							{ name: 'Windows', value: 'windows' }, { name: 'Windows Legacy', value: 'windows_legacy' },
						],
					},
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Resolved', name: 'resolved', type: 'boolean', default: false, description: 'Whether threat is resolved' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{
						displayName: 'Sort By', name: 'sortBy', type: 'options', default: 'createdAt',
						options: [
							{ name: 'ID', value: 'id' }, { name: 'Created At', value: 'createdAt' },
							{ name: 'Site Name', value: 'siteName' }, { name: 'Agent Computer Name', value: 'agentComputerName' },
						],
					},
					{
						displayName: 'Sort Order', name: 'sortOrder', type: 'options', default: 'desc',
						options: [{ name: 'Ascending', value: 'asc' }, { name: 'Descending', value: 'desc' }],
					},
					{ displayName: 'Threat IDs', name: 'ids', type: 'string', default: '', description: 'List of Threat IDs (comma-separated)' },
					{ displayName: 'Updated At (After)', name: 'updatedAt__gte', type: 'dateTime', default: '', description: 'Return threats updated at or after this date/time' },
					{ displayName: 'Updated At (Before)', name: 'updatedAt__lte', type: 'dateTime', default: '', description: 'Return threats updated at or before this date/time' },
				],
			},

			// Mitigate Threat Options
			{
				displayName: 'Mitigation Action',
				name: 'mitigationAction',
				type: 'options',
				displayOptions: { show: { resource: ['threat'], operation: ['mitigateThreat'] } },
				options: [
					{ name: 'Kill', value: 'kill', description: 'Kill the threat process' },
					{ name: 'Quarantine', value: 'quarantine', description: 'Quarantine the threat' },
					{ name: 'Remediate', value: 'remediate', description: 'Remediate the threat (macOS/Windows)' },
					{ name: 'Rollback Remediation', value: 'rollback-remediation', description: 'Rollback remediation (Windows only)' },
					{ name: 'Un-Quarantine', value: 'un-quarantine', description: 'Release from quarantine' },
					{ name: 'Network Quarantine', value: 'network-quarantine', description: 'Network quarantine the threat' },
				],
				default: 'quarantine',
			},
			{
				displayName: 'Target By',
				name: 'threatTargetBy',
				type: 'options',
				displayOptions: { show: { resource: ['threat'], operation: ['mitigateThreat'] } },
				options: [
					{ name: 'Threat IDs', value: 'ids', description: 'Target specific threats by their IDs' },
					{ name: 'Filter', value: 'filter', description: 'Target threats matching filter criteria' },
				],
				default: 'ids',
			},
			{
				displayName: 'Threat IDs',
				name: 'threatIds',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['threat'], operation: ['mitigateThreat'], threatTargetBy: ['ids'] } },
				default: '',
				description: 'Threat ID list (comma-separated)',
			},
			{
				displayName: 'Mitigation Filters',
				name: 'mitigationFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['threat'], operation: ['mitigateThreat'], threatTargetBy: ['filter'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Agent IDs', name: 'agentIds', type: 'string', default: '', description: 'List of Agent IDs (comma-separated)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
				],
			},

			// ============================================
			//         DEVICE CONTROL OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'deviceControlFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['deviceControl'], operation: ['getDeviceRules'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{
						displayName: 'Actions', name: 'actions', type: 'multiOptions', default: [],
						options: [
							{ name: 'Allow', value: 'Allow' }, { name: 'Block', value: 'Block' }, { name: 'Read Only', value: 'Read-Only' },
						],
					},
					{
						displayName: 'Device Classes', name: 'deviceClasses', type: 'multiOptions', default: [],
						options: [
							{ name: 'Any', value: 'Any' }, { name: 'Mass Storage', value: 'Mass Storage' }, { name: 'Printer', value: 'Printer' },
							{ name: 'Portable Device', value: 'Portable Device' }, { name: 'Communication', value: 'Communication' },
						],
					},
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{
						displayName: 'Interfaces', name: 'interfaces', type: 'multiOptions', default: [],
						options: [
							{ name: 'USB', value: 'USB' }, { name: 'Bluetooth', value: 'Bluetooth' },
							{ name: 'Thunderbolt', value: 'Thunderbolt' }, { name: 'eSATA', value: 'eSATA' },
						],
					},
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Rule Name', name: 'ruleName', type: 'string', default: '', description: 'Filter by rule name' },
					{
						displayName: 'Scopes', name: 'scopes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Account', value: 'account' }, { name: 'Global', value: 'global' },
							{ name: 'Group', value: 'group' }, { name: 'Site', value: 'site' },
						],
					},
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{
						displayName: 'Statuses', name: 'statuses', type: 'multiOptions', default: [],
						options: [{ name: 'Enabled', value: 'Enabled' }, { name: 'Disabled', value: 'Disabled' }],
					},
				],
			},

			// Create Rule Options
			{
				displayName: 'Rule Name',
				name: 'ruleName',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'] } },
				default: '',
				description: 'Name of the device control rule',
			},
			{
				displayName: 'Interface',
				name: 'interface',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'] } },
				options: [
					{ name: 'USB', value: 'USB' },
					{ name: 'Bluetooth', value: 'Bluetooth' },
					{ name: 'Thunderbolt', value: 'Thunderbolt' },
					{ name: 'eSATA', value: 'eSATA' },
				],
				default: 'USB',
				description: 'Device interface type',
			},
			{
				displayName: 'Action',
				name: 'ruleAction',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'] } },
				options: [
					{ name: 'Allow', value: 'Allow' },
					{ name: 'Block', value: 'Block' },
					{ name: 'Read Only', value: 'Read-Only' },
				],
				default: 'Block',
				description: 'Action to apply when device matches',
			},
			{
				displayName: 'Rule Type',
				name: 'ruleType',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'] } },
				options: [
					{ name: 'Device Class', value: 'class' },
					{ name: 'Vendor ID', value: 'vendorId' },
					{ name: 'Product ID', value: 'productId' },
					{ name: 'Device ID', value: 'deviceId' },
					{ name: 'Bluetooth Version', value: 'bluetoothVersion' },
				],
				default: 'class',
				description: 'Type of rule matching',
			},
			{
				displayName: 'Device Class',
				name: 'deviceClass',
				type: 'options',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleType: ['class'] } },
				options: [
					{ name: 'Any', value: 'Any' },
					{ name: 'Mass Storage', value: 'Mass Storage' },
					{ name: 'Printer', value: 'Printer' },
					{ name: 'Portable Device', value: 'Portable Device' },
					{ name: 'Communication', value: 'Communication' },
				],
				default: 'Mass Storage',
				description: 'Device class to match',
			},
			{
				displayName: 'Vendor ID',
				name: 'vendorId',
				type: 'string',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleType: ['vendorId', 'productId', 'deviceId'] } },
				default: '',
				description: 'USB Vendor ID (hex format, e.g., 0x1234)',
			},
			{
				displayName: 'Product ID',
				name: 'productId',
				type: 'string',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleType: ['productId', 'deviceId'] } },
				default: '',
				description: 'USB Product ID (hex format, e.g., 0x5678)',
			},
			{
				displayName: 'Bluetooth Version',
				name: 'bluetoothVersion',
				type: 'options',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleType: ['bluetoothVersion'], interface: ['Bluetooth'] } },
				options: [
					{ name: 'Version 1', value: '1' },
					{ name: 'Version 2', value: '2' },
					{ name: 'Version 3', value: '3' },
					{ name: 'Version 4', value: '4' },
					{ name: 'Version 5', value: '5' },
				],
				default: '4',
				description: 'Bluetooth version to match',
			},
			{
				displayName: 'Scope',
				name: 'ruleScope',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'] } },
				options: [
					{ name: 'Global (Tenant)', value: 'tenant' },
					{ name: 'Account', value: 'account' },
					{ name: 'Site', value: 'site' },
					{ name: 'Group', value: 'group' },
				],
				default: 'site',
				description: 'Scope level for the rule',
			},
			{
				displayName: 'Account IDs',
				name: 'createRuleAccountIds',
				type: 'string',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleScope: ['account'] } },
				default: '',
				description: 'Account IDs for account-scoped rules (comma-separated)',
			},
			{
				displayName: 'Site IDs',
				name: 'createRuleSiteIds',
				type: 'string',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleScope: ['site'] } },
				default: '',
				description: 'Site IDs for site-scoped rules (comma-separated)',
			},
			{
				displayName: 'Group IDs',
				name: 'createRuleGroupIds',
				type: 'string',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'], ruleScope: ['group'] } },
				default: '',
				description: 'Group IDs for group-scoped rules (comma-separated)',
			},
			{
				displayName: 'Status',
				name: 'ruleStatus',
				type: 'options',
				displayOptions: { show: { resource: ['deviceControl'], operation: ['createRule'] } },
				options: [
					{ name: 'Enabled', value: 'Enabled' },
					{ name: 'Disabled', value: 'Disabled' },
				],
				default: 'Enabled',
				description: 'Initial status of the rule',
			},

			// Update Rule Options
			{
				displayName: 'Rule ID',
				name: 'updateRuleId',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['updateRule'] } },
				default: '',
				description: 'ID of the rule to update',
			},
			{
				displayName: 'Update Fields',
				name: 'updateFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				displayOptions: { show: { resource: ['deviceControl'], operation: ['updateRule'] } },
				options: [
					{ displayName: 'Rule Name', name: 'ruleName', type: 'string', default: '', description: 'New name for the rule' },
					{
						displayName: 'Action', name: 'action', type: 'options', default: 'Block',
						options: [
							{ name: 'Allow', value: 'Allow' }, { name: 'Block', value: 'Block' }, { name: 'Read Only', value: 'Read-Only' },
						],
					},
					{
						displayName: 'Status', name: 'status', type: 'options', default: 'Enabled',
						options: [{ name: 'Enabled', value: 'Enabled' }, { name: 'Disabled', value: 'Disabled' }],
					},
					{
						displayName: 'Device Class', name: 'deviceClass', type: 'options', default: 'Any',
						options: [
							{ name: 'Any', value: 'Any' }, { name: 'Mass Storage', value: 'Mass Storage' },
							{ name: 'Printer', value: 'Printer' }, { name: 'Portable Device', value: 'Portable Device' },
							{ name: 'Communication', value: 'Communication' },
						],
					},
					{ displayName: 'Vendor ID', name: 'vendorId', type: 'string', default: '', description: 'USB Vendor ID' },
					{ displayName: 'Product ID', name: 'productId', type: 'string', default: '', description: 'USB Product ID' },
				],
			},

			// Delete Rules Options
			{
				displayName: 'Rule IDs',
				name: 'deleteRuleIds',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['deviceControl'], operation: ['deleteRules'] } },
				default: '',
				description: 'IDs of rules to delete (comma-separated)',
			},

			// Get Device Events Filters
			{
				displayName: 'Filters',
				name: 'deviceEventFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['deviceControl'], operation: ['getDeviceEvents'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Agent IDs', name: 'agentIds', type: 'string', default: '', description: 'List of Agent IDs (comma-separated)' },
					{ displayName: 'Computer Name Contains', name: 'computerName__contains', type: 'string', default: '', description: 'Free-text filter by computer name' },
					{
						displayName: 'Event Types', name: 'eventTypes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Blocked', value: 'blocked' },
							{ name: 'Allowed', value: 'allowed' },
							{ name: 'Read Only', value: 'read-only' },
						],
					},
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{
						displayName: 'Interfaces', name: 'interfaces', type: 'multiOptions', default: [],
						options: [
							{ name: 'USB', value: 'USB' }, { name: 'Bluetooth', value: 'Bluetooth' },
							{ name: 'Thunderbolt', value: 'Thunderbolt' }, { name: 'eSATA', value: 'eSATA' },
						],
					},
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Rule IDs', name: 'ruleIds', type: 'string', default: '', description: 'Filter by specific rule IDs (comma-separated)' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{ displayName: 'Created At Between', name: 'createdAt__between', type: 'string', default: '', description: 'Date range (format: from_timestamp-to_timestamp)' },
				],
			},

			// ============================================
			//         ACTIVITY OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'activityFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['activity'], operation: ['getActivities'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Activity Types', name: 'activityTypes', type: 'string', default: '', description: 'Activity type IDs (comma-separated)' },
					{ displayName: 'Agent IDs', name: 'agentIds', type: 'string', default: '', description: 'List of Agent IDs (comma-separated)' },
					{ displayName: 'Created At Between', name: 'createdAt__between', type: 'string', default: '', description: 'Date range (format: from_timestamp-to_timestamp)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'Include Hidden', name: 'includeHidden', type: 'boolean', default: false, description: 'Whether to include hidden activities' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{ displayName: 'Threat IDs', name: 'threatIds', type: 'string', default: '', description: 'List of Threat IDs (comma-separated)' },
					{ displayName: 'User Emails', name: 'userEmails', type: 'string', default: '', description: 'User emails (comma-separated)' },
				],
			},

			// ============================================
			//         EXCLUSION OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'exclusionFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['exclusion'], operation: ['getExclusions'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'IDs', name: 'ids', type: 'string', default: '', description: 'Exclusion IDs (comma-separated)' },
					{
						displayName: 'OS Types', name: 'osTypes', type: 'multiOptions', default: [],
						options: [
							{ name: 'Linux', value: 'linux' }, { name: 'macOS', value: 'macos' },
							{ name: 'Windows', value: 'windows' }, { name: 'Windows Legacy', value: 'windows_legacy' },
						],
					},
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
					{
						displayName: 'Types', name: 'types', type: 'multiOptions', default: [],
						options: [
							{ name: 'Path', value: 'path' },
							{ name: 'Certificate', value: 'certificate' },
							{ name: 'Browser', value: 'browser' },
							{ name: 'File Type', value: 'file_type' },
							{ name: 'White Hash', value: 'white_hash' },
						],
					},
					{ displayName: 'Value', name: 'value', type: 'string', default: '', description: 'Filter by exclusion value' },
				],
			},

			// Create Exclusion Options
			{
				displayName: 'Exclusion Type',
				name: 'exclusionType',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'] } },
				options: [
					{ name: 'Path', value: 'path' },
					{ name: 'Certificate', value: 'certificate' },
					{ name: 'Browser', value: 'browser' },
					{ name: 'File Type', value: 'file_type' },
					{ name: 'White Hash', value: 'white_hash' },
				],
				default: 'path',
				description: 'Type of exclusion to create',
			},
			{
				displayName: 'OS Type',
				name: 'exclusionOsType',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'] } },
				options: [
					{ name: 'Linux', value: 'linux' },
					{ name: 'macOS', value: 'macos' },
					{ name: 'Windows', value: 'windows' },
					{ name: 'Windows Legacy', value: 'windows_legacy' },
				],
				default: 'windows',
				description: 'Operating system for the exclusion',
			},
			{
				displayName: 'Value',
				name: 'exclusionValue',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'] } },
				default: '',
				description: 'Value to exclude (path, hash, certificate signer, etc.)',
			},
			{
				displayName: 'Scope',
				name: 'exclusionScope',
				type: 'options',
				required: true,
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'] } },
				options: [
					{ name: 'Global (Tenant)', value: 'tenant' },
					{ name: 'Account', value: 'account' },
					{ name: 'Site', value: 'site' },
					{ name: 'Group', value: 'group' },
				],
				default: 'site',
				description: 'Scope level for the exclusion',
			},
			{
				displayName: 'Account IDs',
				name: 'exclusionAccountIds',
				type: 'string',
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'], exclusionScope: ['account'] } },
				default: '',
				description: 'Account IDs (comma-separated)',
			},
			{
				displayName: 'Site IDs',
				name: 'exclusionSiteIds',
				type: 'string',
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'], exclusionScope: ['site'] } },
				default: '',
				description: 'Site IDs (comma-separated)',
			},
			{
				displayName: 'Group IDs',
				name: 'exclusionGroupIds',
				type: 'string',
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'], exclusionScope: ['group'] } },
				default: '',
				description: 'Group IDs (comma-separated)',
			},
			{
				displayName: 'Description',
				name: 'exclusionDescription',
				type: 'string',
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'] } },
				default: '',
				description: 'Description of the exclusion',
			},
			{
				displayName: 'Mode',
				name: 'exclusionMode',
				type: 'options',
				displayOptions: { show: { resource: ['exclusion'], operation: ['createExclusion'], exclusionType: ['path'] } },
				options: [
					{ name: 'Suppress', value: 'suppress' },
					{ name: 'Suppress Dynamic Only', value: 'suppress_dynamic_only' },
					{ name: 'Suppress DFI Only', value: 'suppress_dfi_only' },
					{ name: 'Disable In-Process Monitor', value: 'disable_in_process_monitor' },
					{ name: 'Disable All Monitors', value: 'disable_all_monitors' },
				],
				default: 'suppress',
				description: 'Exclusion mode (path exclusions only)',
			},

			// Update Exclusion Options
			{
				displayName: 'Exclusion ID',
				name: 'updateExclusionId',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['exclusion'], operation: ['updateExclusion'] } },
				default: '',
				description: 'ID of the exclusion to update',
			},
			{
				displayName: 'Update Fields',
				name: 'exclusionUpdateFields',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				displayOptions: { show: { resource: ['exclusion'], operation: ['updateExclusion'] } },
				options: [
					{ displayName: 'Description', name: 'description', type: 'string', default: '', description: 'New description' },
					{ displayName: 'Value', name: 'value', type: 'string', default: '', description: 'New value' },
					{
						displayName: 'Mode', name: 'mode', type: 'options', default: 'suppress',
						options: [
							{ name: 'Suppress', value: 'suppress' },
							{ name: 'Suppress Dynamic Only', value: 'suppress_dynamic_only' },
							{ name: 'Disable All Monitors', value: 'disable_all_monitors' },
						],
					},
				],
			},

			// Delete Exclusions Options
			{
				displayName: 'Exclusion IDs',
				name: 'deleteExclusionIds',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['exclusion'], operation: ['deleteExclusions'] } },
				default: '',
				description: 'IDs of exclusions to delete (comma-separated)',
			},

			// ============================================
			//         GROUP OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'groupFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['group'], operation: ['getGroups'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'Filter by specific Group IDs (comma-separated)' },
					{ displayName: 'Is Default', name: 'isDefault', type: 'boolean', default: false, description: 'Whether to filter by default groups' },
					{ displayName: 'Name', name: 'name', type: 'string', default: '', description: 'Filter by group name' },
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
				],
			},

			// Move Agents to Group Options
			{
				displayName: 'Target Group ID',
				name: 'moveToGroupId',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['group'], operation: ['moveAgents'] } },
				default: '',
				description: 'ID of the group to move agents to',
			},
			{
				displayName: 'Target By',
				name: 'moveAgentsTargetBy',
				type: 'options',
				displayOptions: { show: { resource: ['group'], operation: ['moveAgents'] } },
				options: [
					{ name: 'Agent IDs', value: 'ids', description: 'Target specific agents by their IDs' },
					{ name: 'Filter', value: 'filter', description: 'Target agents matching filter criteria' },
				],
				default: 'ids',
			},
			{
				displayName: 'Agent IDs',
				name: 'moveAgentIds',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['group'], operation: ['moveAgents'], moveAgentsTargetBy: ['ids'] } },
				default: '',
				description: 'Agent IDs to move (comma-separated)',
			},
			{
				displayName: 'Agent Filters',
				name: 'moveAgentFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['group'], operation: ['moveAgents'], moveAgentsTargetBy: ['filter'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Computer Name Contains', name: 'computerName__contains', type: 'string', default: '', description: 'Free-text filter by computer name' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
				],
			},

			// ============================================
			//         HASH OPTIONS
			// ============================================
			{
				displayName: 'Hash',
				name: 'hashValue',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['hash'], operation: ['getVerdict'] } },
				default: '',
				description: 'SHA1 hash to check (40 characters)',
			},

			// ============================================
			//         SITE OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'siteFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['site'], operation: ['getSites'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Admin Only', name: 'adminOnly', type: 'boolean', default: false, description: 'Whether to show only sites the user can manage' },
					{ displayName: 'Available Modules', name: 'availableMovesToSites', type: 'boolean', default: false, description: 'Whether to show only sites available for moving agents' },
					{ displayName: 'Name', name: 'name', type: 'string', default: '', description: 'Filter by site name' },
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'Filter by specific Site IDs (comma-separated)' },
					{
						displayName: 'Site Type', name: 'siteType', type: 'options', default: 'Paid',
						options: [
							{ name: 'Paid', value: 'Paid' },
							{ name: 'Trial', value: 'Trial' },
						],
					},
					{
						displayName: 'States', name: 'states', type: 'multiOptions', default: [],
						options: [
							{ name: 'Active', value: 'active' },
							{ name: 'Deleted', value: 'deleted' },
							{ name: 'Expired', value: 'expired' },
						],
					},
				],
			},

			// ============================================
			//         ADDITIONAL AGENT ACTION OPTIONS
			// ============================================

			// Move to Site Options
			{
				displayName: 'Target Site ID',
				name: 'moveToSiteId',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['agent'], operation: ['moveToSite'] } },
				default: '',
				description: 'ID of the site to move agents to',
			},

			// Update Software Options
			{
				displayName: 'Package Type',
				name: 'updatePackageType',
				type: 'options',
				displayOptions: { show: { resource: ['agent'], operation: ['updateSoftware'] } },
				options: [
					{ name: 'Agent', value: 'Agent' },
					{ name: 'Ranger', value: 'Ranger' },
				],
				default: 'Agent',
				description: 'Type of software package to update',
			},

			// ============================================
			//         TAG OPTIONS
			// ============================================
			{
				displayName: 'Filters',
				name: 'tagFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['tag'], operation: ['getTags'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
				],
			},

			// Manage Tags Options
			{
				displayName: 'Tag Action',
				name: 'tagAction',
				type: 'options',
				displayOptions: { show: { resource: ['tag'], operation: ['manageTags'] } },
				options: [
					{ name: 'Add', value: 'add', description: 'Add tags to agents (if not already present)' },
					{ name: 'Remove', value: 'remove', description: 'Remove tags from agents (if present)' },
					{ name: 'Override', value: 'override', description: 'Override existing tags with the same key' },
				],
				default: 'add',
			},
			{
				displayName: 'Tags',
				name: 'tags',
				type: 'fixedCollection',
				typeOptions: { multipleValues: true },
				displayOptions: { show: { resource: ['tag'], operation: ['manageTags'] } },
				default: {},
				options: [
					{
						name: 'tagValues',
						displayName: 'Tags',
						values: [
							{ displayName: 'Key', name: 'key', type: 'string', default: '', description: 'Tag key' },
							{ displayName: 'Value', name: 'value', type: 'string', default: '', description: 'Tag value' },
						],
					},
				],
			},
			{
				displayName: 'Target By',
				name: 'tagTargetBy',
				type: 'options',
				displayOptions: { show: { resource: ['tag'], operation: ['manageTags'] } },
				options: [
					{ name: 'Agent IDs', value: 'ids', description: 'Target specific agents by their IDs' },
					{ name: 'Filter', value: 'filter', description: 'Target agents matching filter criteria' },
				],
				default: 'ids',
			},
			{
				displayName: 'Agent IDs',
				name: 'tagAgentIds',
				type: 'string',
				required: true,
				displayOptions: { show: { resource: ['tag'], operation: ['manageTags'], tagTargetBy: ['ids'] } },
				default: '',
				description: 'Agent ID list (comma-separated)',
			},
			{
				displayName: 'Tag Filters',
				name: 'tagActionFilters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: { show: { resource: ['tag'], operation: ['manageTags'], tagTargetBy: ['filter'] } },
				options: [
					{ displayName: 'Account IDs', name: 'accountIds', type: 'string', default: '', description: 'List of Account IDs (comma-separated)' },
					{ displayName: 'Group IDs', name: 'groupIds', type: 'string', default: '', description: 'List of Group IDs (comma-separated)' },
					{ displayName: 'Query', name: 'query', type: 'string', default: '', description: 'Free-text search term' },
					{ displayName: 'Site IDs', name: 'siteIds', type: 'string', default: '', description: 'List of Site IDs (comma-separated)' },
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;

		const credentials = await this.getCredentials('sentinelOneApi');
		const baseUrl = credentials.apiUrl as string;

		for (let i = 0; i < items.length; i++) {
			try {
				// ============================================
				//              AGENT RESOURCE
				// ============================================
				if (resource === 'agent') {
					if (operation === 'getAgents') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('filters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/agents`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(agent => returnData.push({ json: agent }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/agents`,
								qs,
								json: true,
							});
							responseData.data?.forEach(agent => returnData.push({ json: agent }));
						}
					}

					if (operation === 'getApplications') {
						const agentIds = this.getNodeParameter('agentIds', i) as string;
						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'GET' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/agents/applications`,
							qs: { ids: agentIds },
							json: true,
						}) as { data: IDataObject[] };
						responseData.data?.forEach(app => returnData.push({ json: app }));
					}

					if (operation === 'getPassphrase') {
						const agentIds = this.getNodeParameter('agentIds', i) as string;
						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'GET' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/agents/passphrases`,
							qs: { ids: agentIds },
							json: true,
						}) as { data: IDataObject[] };
						responseData.data?.forEach(passphrase => returnData.push({ json: passphrase }));
					}

					if (['abortScan', 'initiateScan', 'connect', 'disconnect', 'decommission', 'disableAgent', 'enableAgent', 'fetchLogs', 'restart', 'shutdown', 'uninstall'].includes(operation)) {
						const targetBy = this.getNodeParameter('targetBy', i) as string;
						const filter: IDataObject = {};

						if (targetBy === 'ids') {
							const agentIds = this.getNodeParameter('actionAgentIds', i) as string;
							filter.ids = agentIds.split(',').map(id => id.trim());
						} else {
							const actionFilters = this.getNodeParameter('actionFilters', i) as IDataObject;
							Object.entries(actionFilters).forEach(([key, value]) => {
								if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
									filter[key] = typeof value === 'string' && key !== 'query' ? value.split(',').map(s => s.trim()) : value;
								}
							});
						}

						const actionEndpoints: Record<string, string> = {
							abortScan: '/web/api/v2.1/agents/actions/abort-scan',
							initiateScan: '/web/api/v2.1/agents/actions/initiate-scan',
							connect: '/web/api/v2.1/agents/actions/connect',
							disconnect: '/web/api/v2.1/agents/actions/disconnect',
							decommission: '/web/api/v2.1/agents/actions/decommission',
							disableAgent: '/web/api/v2.1/agents/actions/disable-agent',
							enableAgent: '/web/api/v2.1/agents/actions/enable-agent',
							fetchLogs: '/web/api/v2.1/agents/actions/fetch-logs',
							restart: '/web/api/v2.1/agents/actions/restart-machine',
							shutdown: '/web/api/v2.1/agents/actions/shutdown',
							uninstall: '/web/api/v2.1/agents/actions/uninstall',
						};

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}${actionEndpoints[operation]}`,
							body: { filter },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'moveToSite') {
						const targetBy = this.getNodeParameter('targetBy', i) as string;
						const targetSiteId = this.getNodeParameter('moveToSiteId', i) as string;
						const filter: IDataObject = {};

						if (targetBy === 'ids') {
							const agentIds = this.getNodeParameter('actionAgentIds', i) as string;
							filter.ids = agentIds.split(',').map(id => id.trim());
						} else {
							const actionFilters = this.getNodeParameter('actionFilters', i) as IDataObject;
							Object.entries(actionFilters).forEach(([key, value]) => {
								if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
									filter[key] = typeof value === 'string' && key !== 'query' ? value.split(',').map(s => s.trim()) : value;
								}
							});
						}

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/agents/actions/move-to-site`,
							body: { filter, data: { targetSiteId } },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'updateSoftware') {
						const targetBy = this.getNodeParameter('targetBy', i) as string;
						const packageType = this.getNodeParameter('updatePackageType', i, 'Agent') as string;
						const filter: IDataObject = {};

						if (targetBy === 'ids') {
							const agentIds = this.getNodeParameter('actionAgentIds', i) as string;
							filter.ids = agentIds.split(',').map(id => id.trim());
						} else {
							const actionFilters = this.getNodeParameter('actionFilters', i) as IDataObject;
							Object.entries(actionFilters).forEach(([key, value]) => {
								if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
									filter[key] = typeof value === 'string' && key !== 'query' ? value.split(',').map(s => s.trim()) : value;
								}
							});
						}

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/agents/actions/update-software`,
							body: { filter, data: { packageType } },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}
				}

				// ============================================
				//              THREAT RESOURCE
				// ============================================
				if (resource === 'threat') {
					if (operation === 'getThreats') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('threatFilters', i) as IDataObject;
						const qs: IDataObject = {};

						// Handle quick range preset — compute createdAt__gte from the selected preset
						const quickRange = filters.createdAt__quickRange as string | undefined;
						if (quickRange && quickRange !== 'none') {
							const now = new Date();
							const msPerDay = 24 * 60 * 60 * 1000;
							const rangeMs: Record<string, number> = {
								last24h: 1 * msPerDay,
								last7d: 7 * msPerDay,
								last14d: 14 * msPerDay,
								last30d: 30 * msPerDay,
								last90d: 90 * msPerDay,
							};
							if (rangeMs[quickRange]) {
								qs['createdAt__gte'] = new Date(now.getTime() - rangeMs[quickRange]).toISOString();
							}
						}

						Object.entries(filters).forEach(([key, value]) => {
							if (key === 'createdAt__quickRange') return;
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/threats`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(threat => returnData.push({ json: threat }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/threats`,
								qs,
								json: true,
							});
							responseData.data?.forEach(threat => returnData.push({ json: threat }));
						}
					}

					if (operation === 'mitigateThreat') {
						const action = this.getNodeParameter('mitigationAction', i) as string;
						const targetBy = this.getNodeParameter('threatTargetBy', i) as string;
						const filter: IDataObject = {};

						if (targetBy === 'ids') {
							const threatIds = this.getNodeParameter('threatIds', i) as string;
							filter.ids = threatIds.split(',').map(id => id.trim());
						} else {
							const mitigationFilters = this.getNodeParameter('mitigationFilters', i) as IDataObject;
							Object.entries(mitigationFilters).forEach(([key, value]) => {
								if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
									filter[key] = typeof value === 'string' && key !== 'query' ? value.split(',').map(s => s.trim()) : value;
								}
							});
						}

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/threats/mitigate/${action}`,
							body: { filter },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}
				}

				// ============================================
				//           DEVICE CONTROL RESOURCE
				// ============================================
				if (resource === 'deviceControl') {
					if (operation === 'getDeviceRules') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('deviceControlFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/device-control`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(rule => returnData.push({ json: rule }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/device-control`,
								qs,
								json: true,
							});
							responseData.data?.forEach(rule => returnData.push({ json: rule }));
						}
					}

					if (operation === 'createRule') {
						const ruleName = this.getNodeParameter('ruleName', i) as string;
						const interfaceType = this.getNodeParameter('interface', i) as string;
						const ruleAction = this.getNodeParameter('ruleAction', i) as string;
						const ruleType = this.getNodeParameter('ruleType', i) as string;
						const ruleScope = this.getNodeParameter('ruleScope', i) as string;
						const ruleStatus = this.getNodeParameter('ruleStatus', i) as string;

						const data: IDataObject = {
							ruleName,
							interface: interfaceType,
							action: ruleAction,
							ruleType,
							status: ruleStatus,
						};

						// Add rule type specific fields
						if (ruleType === 'class') {
							const deviceClass = this.getNodeParameter('deviceClass', i, 'Any') as string;
							data.deviceClass = deviceClass;
						} else if (['vendorId', 'productId', 'deviceId'].includes(ruleType)) {
							const vendorId = this.getNodeParameter('vendorId', i, '') as string;
							if (vendorId) data.vendorId = vendorId;
							if (['productId', 'deviceId'].includes(ruleType)) {
								const productId = this.getNodeParameter('productId', i, '') as string;
								if (productId) data.productId = productId;
							}
						} else if (ruleType === 'bluetoothVersion') {
							const bluetoothVersion = this.getNodeParameter('bluetoothVersion', i, '4') as string;
							data.bluetoothVersion = bluetoothVersion;
						}

						// Build filter for scope
						const filter: IDataObject = {};
						if (ruleScope === 'tenant') {
							filter.tenant = true;
						} else if (ruleScope === 'account') {
							const accountIds = this.getNodeParameter('createRuleAccountIds', i, '') as string;
							if (accountIds) filter.accountIds = accountIds.split(',').map(id => id.trim());
						} else if (ruleScope === 'site') {
							const siteIds = this.getNodeParameter('createRuleSiteIds', i, '') as string;
							if (siteIds) filter.siteIds = siteIds.split(',').map(id => id.trim());
						} else if (ruleScope === 'group') {
							const groupIds = this.getNodeParameter('createRuleGroupIds', i, '') as string;
							if (groupIds) filter.groupIds = groupIds.split(',').map(id => id.trim());
						}

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/device-control`,
							body: { data, filter },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'updateRule') {
						const ruleId = this.getNodeParameter('updateRuleId', i) as string;
						const updateFields = this.getNodeParameter('updateFields', i) as IDataObject;

						const data: IDataObject = {};
						Object.entries(updateFields).forEach(([key, value]) => {
							if (value !== undefined && value !== '') {
								data[key] = value;
							}
						});

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'PUT' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/device-control/${ruleId}`,
							body: { data },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'deleteRules') {
						const ruleIds = this.getNodeParameter('deleteRuleIds', i) as string;
						const ids = ruleIds.split(',').map(id => id.trim());

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'DELETE' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/device-control`,
							body: { filter: { ids } },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'getDeviceEvents') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('deviceEventFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/device-control/events`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(event => returnData.push({ json: event }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/device-control/events`,
								qs,
								json: true,
							});
							responseData.data?.forEach(event => returnData.push({ json: event }));
						}
					}
				}

				// ============================================
				//              TAG RESOURCE
				// ============================================
				if (resource === 'tag') {
					if (operation === 'getTags') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('tagFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/agents/tags`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(tag => returnData.push({ json: tag }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/agents/tags`,
								qs,
								json: true,
							});
							responseData.data?.forEach(tag => returnData.push({ json: tag }));
						}
					}

					if (operation === 'manageTags') {
						const tagAction = this.getNodeParameter('tagAction', i) as string;
						const tagsData = this.getNodeParameter('tags', i) as { tagValues: Array<{ key: string; value: string }> };
						const targetBy = this.getNodeParameter('tagTargetBy', i) as string;
						const filter: IDataObject = {};

						if (targetBy === 'ids') {
							const agentIds = this.getNodeParameter('tagAgentIds', i) as string;
							filter.ids = agentIds.split(',').map(id => id.trim());
						} else {
							const tagFilters = this.getNodeParameter('tagActionFilters', i) as IDataObject;
							Object.entries(tagFilters).forEach(([key, value]) => {
								if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
									filter[key] = typeof value === 'string' && key !== 'query' ? value.split(',').map(s => s.trim()) : value;
								}
							});
						}

						const tags = tagsData.tagValues?.map(t => ({ key: t.key, value: t.value })) || [];

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/agents/actions/manage-tags`,
							body: {
								filter,
								data: {
									type: tagAction,
									tags,
								},
							},
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}
				}

				// ============================================
				//              ACTIVITY RESOURCE
				// ============================================
				if (resource === 'activity') {
					if (operation === 'getActivities') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('activityFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/activities`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(activity => returnData.push({ json: activity }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/activities`,
								qs,
								json: true,
							});
							responseData.data?.forEach(activity => returnData.push({ json: activity }));
						}
					}

					if (operation === 'getActivityTypes') {
						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'GET' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/activities/types`,
							json: true,
						}) as { data: IDataObject[] };
						responseData.data?.forEach(type => returnData.push({ json: type }));
					}
				}

				// ============================================
				//              EXCLUSION RESOURCE
				// ============================================
				if (resource === 'exclusion') {
					if (operation === 'getExclusions') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('exclusionFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/exclusions`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(exclusion => returnData.push({ json: exclusion }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/exclusions`,
								qs,
								json: true,
							});
							responseData.data?.forEach(exclusion => returnData.push({ json: exclusion }));
						}
					}

					if (operation === 'createExclusion') {
						const exclusionType = this.getNodeParameter('exclusionType', i) as string;
						const osType = this.getNodeParameter('exclusionOsType', i) as string;
						const value = this.getNodeParameter('exclusionValue', i) as string;
						const scope = this.getNodeParameter('exclusionScope', i) as string;
						const description = this.getNodeParameter('exclusionDescription', i, '') as string;

						const data: IDataObject = {
							type: exclusionType,
							osType,
							value,
						};

						if (description) data.description = description;

						if (exclusionType === 'path') {
							const mode = this.getNodeParameter('exclusionMode', i, 'suppress') as string;
							data.mode = mode;
						}

						const filter: IDataObject = {};
						if (scope === 'tenant') {
							filter.tenant = true;
						} else if (scope === 'account') {
							const accountIds = this.getNodeParameter('exclusionAccountIds', i, '') as string;
							if (accountIds) filter.accountIds = accountIds.split(',').map(id => id.trim());
						} else if (scope === 'site') {
							const siteIds = this.getNodeParameter('exclusionSiteIds', i, '') as string;
							if (siteIds) filter.siteIds = siteIds.split(',').map(id => id.trim());
						} else if (scope === 'group') {
							const groupIds = this.getNodeParameter('exclusionGroupIds', i, '') as string;
							if (groupIds) filter.groupIds = groupIds.split(',').map(id => id.trim());
						}

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'POST' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/exclusions`,
							body: { data, filter },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'updateExclusion') {
						const exclusionId = this.getNodeParameter('updateExclusionId', i) as string;
						const updateFields = this.getNodeParameter('exclusionUpdateFields', i) as IDataObject;

						const data: IDataObject = {};
						Object.entries(updateFields).forEach(([key, value]) => {
							if (value !== undefined && value !== '') {
								data[key] = value;
							}
						});

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'PUT' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/exclusions`,
							body: { data, filter: { ids: [exclusionId] } },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}

					if (operation === 'deleteExclusions') {
						const exclusionIds = this.getNodeParameter('deleteExclusionIds', i) as string;
						const ids = exclusionIds.split(',').map(id => id.trim());

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'DELETE' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/exclusions`,
							body: { filter: { ids } },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}
				}

				// ============================================
				//              GROUP RESOURCE
				// ============================================
				if (resource === 'group') {
					if (operation === 'getGroups') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('groupFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: IDataObject[]; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/groups`,
									qs,
									json: true,
								});
								if (responseData.data) allData.push(...responseData.data);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(group => returnData.push({ json: group }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/groups`,
								qs,
								json: true,
							});
							responseData.data?.forEach(group => returnData.push({ json: group }));
						}
					}

					if (operation === 'moveAgents') {
						const groupId = this.getNodeParameter('moveToGroupId', i) as string;
						const targetBy = this.getNodeParameter('moveAgentsTargetBy', i) as string;
						const filter: IDataObject = {};

						if (targetBy === 'ids') {
							const agentIds = this.getNodeParameter('moveAgentIds', i) as string;
							filter.ids = agentIds.split(',').map(id => id.trim());
						} else {
							const moveFilters = this.getNodeParameter('moveAgentFilters', i) as IDataObject;
							Object.entries(moveFilters).forEach(([key, value]) => {
								if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
									filter[key] = typeof value === 'string' && key !== 'query' ? value.split(',').map(s => s.trim()) : value;
								}
							});
						}

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'PUT' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/groups/${groupId}/move-agents`,
							body: { filter },
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}
				}

				// ============================================
				//              HASH RESOURCE
				// ============================================
				if (resource === 'hash') {
					if (operation === 'getVerdict') {
						const hash = this.getNodeParameter('hashValue', i) as string;

						const responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
							method: 'GET' as IHttpRequestMethods,
							url: `${baseUrl}/web/api/v2.1/hashes/${hash}/verdict`,
							json: true,
						}) as { data: IDataObject };
						returnData.push({ json: responseData.data || responseData });
					}
				}

				// ============================================
				//              SITE RESOURCE
				// ============================================
				if (resource === 'site') {
					if (operation === 'getSites') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('siteFilters', i) as IDataObject;
						const qs: IDataObject = {};

						Object.entries(filters).forEach(([key, value]) => {
							if (value !== undefined && value !== '' && !(Array.isArray(value) && value.length === 0)) {
								qs[key] = Array.isArray(value) ? (value as string[]).join(',') : value;
							}
						});

						const allData: IDataObject[] = [];
						let responseData: { data: { sites: IDataObject[] }; pagination?: { nextCursor?: string } };

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/sites`,
									qs,
									json: true,
								});
								if (responseData.data?.sites) allData.push(...responseData.data.sites);
								if (responseData.pagination?.nextCursor) qs.cursor = responseData.pagination.nextCursor;
							} while (responseData.pagination?.nextCursor);
							allData.forEach(site => returnData.push({ json: site }));
						} else {
							qs.limit = this.getNodeParameter('limit', i) as number;
							responseData = await this.helpers.httpRequestWithAuthentication.call(this, 'sentinelOneApi', {
								method: 'GET' as IHttpRequestMethods,
								url: `${baseUrl}/web/api/v2.1/sites`,
								qs,
								json: true,
							});
							responseData.data?.sites?.forEach(site => returnData.push({ json: site }));
						}
					}
				}

			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message } });
					continue;
				}
				throw new NodeApiError(this.getNode(), error as JsonObject);
			}
		}

		return [returnData];
	}
}

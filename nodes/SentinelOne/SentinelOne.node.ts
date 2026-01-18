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
					{ name: 'Agent', value: 'agent' },
					{ name: 'Device Control', value: 'deviceControl' },
					{ name: 'Tag', value: 'tag' },
					{ name: 'Threat', value: 'threat' },
				],
				default: 'agent',
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
						name: 'Connect to Network',
						value: 'connect',
						description: 'Reconnect agents to the network after isolation',
						action: 'Connect agents to network',
					},
					{
						name: 'Disconnect from Network',
						value: 'disconnect',
						description: 'Isolate (quarantine) agents from the network',
						action: 'Disconnect agents from network',
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
						name: 'Initiate Scan',
						value: 'initiateScan',
						description: 'Run a Full Disk Scan on Agents that match the filter',
						action: 'Initiate full disk scan',
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
						name: 'Get Device Rules',
						value: 'getDeviceRules',
						description: 'Get the Device Control rules that match the filter',
						action: 'Get device control rules',
					},
				],
				default: 'getDeviceRules',
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
						resource: ['agent', 'threat', 'deviceControl', 'tag'],
						operation: ['getAgents', 'getThreats', 'getDeviceRules', 'getTags'],
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
						resource: ['agent', 'threat', 'deviceControl', 'tag'],
						operation: ['getAgents', 'getThreats', 'getDeviceRules', 'getTags'],
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
						operation: ['initiateScan', 'connect', 'disconnect', 'restart', 'shutdown', 'uninstall'],
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
						operation: ['initiateScan', 'connect', 'disconnect', 'restart', 'shutdown', 'uninstall'],
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
						operation: ['initiateScan', 'connect', 'disconnect', 'restart', 'shutdown', 'uninstall'],
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

					if (['initiateScan', 'connect', 'disconnect', 'restart', 'shutdown', 'uninstall'].includes(operation)) {
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
							initiateScan: '/web/api/v2.1/agents/actions/initiate-scan',
							connect: '/web/api/v2.1/agents/actions/connect',
							disconnect: '/web/api/v2.1/agents/actions/disconnect',
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
				}

				// ============================================
				//              THREAT RESOURCE
				// ============================================
				if (resource === 'threat') {
					if (operation === 'getThreats') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('threatFilters', i) as IDataObject;
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

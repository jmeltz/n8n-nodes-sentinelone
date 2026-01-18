import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IHttpRequestMethods,
	NodeApiError,
} from 'n8n-workflow';

export class SentinelOne implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'SentinelOne',
		name: 'sentinelOne',
		icon: 'file:sentinelone.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
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
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Agent',
						value: 'agent',
					},
				],
				default: 'agent',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['agent'],
					},
				},
				options: [
					{
						name: 'Get Agents',
						value: 'getAgents',
						description: 'Get the Agents and their data that match the filter',
						action: 'Get agents',
					},
				],
				default: 'getAgents',
			},
			// Pagination options
			{
				displayName: 'Return All',
				name: 'returnAll',
				type: 'boolean',
				displayOptions: {
					show: {
						resource: ['agent'],
						operation: ['getAgents'],
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
						resource: ['agent'],
						operation: ['getAgents'],
						returnAll: [false],
					},
				},
				typeOptions: {
					minValue: 1,
					maxValue: 1000,
				},
				default: 50,
				description: 'Max number of results to return',
			},
			// Filters
			{
				displayName: 'Filters',
				name: 'filters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				displayOptions: {
					show: {
						resource: ['agent'],
						operation: ['getAgents'],
					},
				},
				options: [
					{
						displayName: 'Account IDs',
						name: 'accountIds',
						type: 'string',
						default: '',
						description: 'List of Account IDs to filter by (comma-separated)',
					},
					{
						displayName: 'Agent Versions',
						name: 'agentVersions',
						type: 'string',
						default: '',
						description: 'Agent versions to include (comma-separated). Example: "2.0.0.0,2.1.5.144".',
					},
					{
						displayName: 'Computer Name Contains',
						name: 'computerName__contains',
						type: 'string',
						default: '',
						description: 'Free-text filter by computer name (comma-separated for multiple values)',
					},
					{
						displayName: 'Count Only',
						name: 'countOnly',
						type: 'boolean',
						default: false,
						description: 'Whether to return only the total count without the actual objects',
					},
					{
						displayName: 'Domains',
						name: 'domains',
						type: 'string',
						default: '',
						description: 'Included network domains (comma-separated). Example: "mybusiness.net,workgroup".',
					},
					{
						displayName: 'External IP Contains',
						name: 'externalIp__contains',
						type: 'string',
						default: '',
						description: 'Free-text filter by visible IP (comma-separated for multiple values)',
					},
					{
						displayName: 'Group IDs',
						name: 'groupIds',
						type: 'string',
						default: '',
						description: 'List of Group IDs to filter by (comma-separated)',
					},
					{
						displayName: 'Infected',
						name: 'infected',
						type: 'boolean',
						default: false,
						description: 'Whether to include only Agents with at least one active threat',
					},
					{
						displayName: 'Is Active',
						name: 'isActive',
						type: 'boolean',
						default: false,
						description: 'Whether to include only active Agents',
					},
					{
						displayName: 'Is Pending Uninstall',
						name: 'isPendingUninstall',
						type: 'boolean',
						default: false,
						description: 'Whether to include only Agents with pending uninstall requests',
					},
					{
						displayName: 'Is Up To Date',
						name: 'isUpToDate',
						type: 'boolean',
						default: false,
						description: 'Whether to include only Agents with updated software',
					},
					{
						displayName: 'Last Active Date Between',
						name: 'lastActiveDate__between',
						type: 'string',
						default: '',
						description: 'Date range for last active date (format: from_timestamp-to_timestamp). Example: "1514978764288-1514978999999".',
					},
					{
						displayName: 'Last Logged In Username Contains',
						name: 'lastLoggedInUserName__contains',
						type: 'string',
						default: '',
						description: 'Free-text filter by username (comma-separated for multiple values)',
					},
					{
						displayName: 'Machine Types',
						name: 'machineTypes',
						type: 'multiOptions',
						options: [
							{ name: 'Desktop', value: 'desktop' },
							{ name: 'ECS Task', value: 'ecs task' },
							{ name: 'Kubernetes Helper', value: 'kubernetes helper' },
							{ name: 'Kubernetes Node', value: 'kubernetes node' },
							{ name: 'Kubernetes Pod', value: 'kubernetes pod' },
							{ name: 'Laptop', value: 'laptop' },
							{ name: 'Server', value: 'server' },
							{ name: 'Storage', value: 'storage' },
							{ name: 'Unknown', value: 'unknown' },
						],
						default: [],
						description: 'Included machine types',
					},
					{
						displayName: 'Network Statuses',
						name: 'networkStatuses',
						type: 'multiOptions',
						options: [
							{ name: 'Connected', value: 'connected' },
							{ name: 'Connecting', value: 'connecting' },
							{ name: 'Disconnected', value: 'disconnected' },
							{ name: 'Disconnecting', value: 'disconnecting' },
						],
						default: [],
						description: 'Included network statuses',
					},
					{
						displayName: 'OS Types',
						name: 'osTypes',
						type: 'multiOptions',
						options: [
							{ name: 'Linux', value: 'linux' },
							{ name: 'macOS', value: 'macos' },
							{ name: 'Windows', value: 'windows' },
							{ name: 'Windows Legacy', value: 'windows_legacy' },
						],
						default: [],
						description: 'Included OS types',
					},
					{
						displayName: 'Query',
						name: 'query',
						type: 'string',
						default: '',
						description: 'A free-text search term that will match applicable attributes (sub-string match)',
					},
					{
						displayName: 'Registered At Between',
						name: 'registeredAt__between',
						type: 'string',
						default: '',
						description: 'Date range for first registration time (format: from_timestamp-to_timestamp). Example: "1514978764288-1514978999999".',
					},
					{
						displayName: 'Scan Statuses',
						name: 'scanStatuses',
						type: 'multiOptions',
						options: [
							{ name: 'Aborted', value: 'aborted' },
							{ name: 'Finished', value: 'finished' },
							{ name: 'None', value: 'none' },
							{ name: 'Started', value: 'started' },
						],
						default: [],
						description: 'Included scan statuses',
					},
					{
						displayName: 'Site IDs',
						name: 'siteIds',
						type: 'string',
						default: '',
						description: 'List of Site IDs to filter by (comma-separated)',
					},
					{
						displayName: 'Sort By',
						name: 'sortBy',
						type: 'options',
						options: [
							{ name: 'Account Name', value: 'accountName' },
							{ name: 'Active Threats', value: 'activeThreats' },
							{ name: 'Agent Version', value: 'agentVersion' },
							{ name: 'Computer Name', value: 'computerName' },
							{ name: 'Created At', value: 'createdAt' },
							{ name: 'Domain', value: 'domain' },
							{ name: 'External IP', value: 'externalIp' },
							{ name: 'Group ID', value: 'groupId' },
							{ name: 'Group Name', value: 'groupName' },
							{ name: 'ID', value: 'id' },
							{ name: 'Is Active', value: 'isActive' },
							{ name: 'Is Up To Date', value: 'isUpToDate' },
							{ name: 'Last Active Date', value: 'lastActiveDate' },
							{ name: 'Last Logged In Username', value: 'lastLoggedInUserName' },
							{ name: 'Machine Type', value: 'machineType' },
							{ name: 'Network Status', value: 'networkStatus' },
							{ name: 'OS Name', value: 'osName' },
							{ name: 'OS Type', value: 'osType' },
							{ name: 'Registered At', value: 'registeredAt' },
							{ name: 'Scan Status', value: 'scanStatus' },
							{ name: 'Site ID', value: 'siteId' },
							{ name: 'Site Name', value: 'siteName' },
							{ name: 'Updated At', value: 'updatedAt' },
							{ name: 'UUID', value: 'uuid' },
						],
						default: 'createdAt',
						description: 'The column to sort the results by',
					},
					{
						displayName: 'Sort Order',
						name: 'sortOrder',
						type: 'options',
						options: [
							{ name: 'Ascending', value: 'asc' },
							{ name: 'Descending', value: 'desc' },
						],
						default: 'asc',
						description: 'Sort direction',
					},
					{
						displayName: 'UUID',
						name: 'uuid',
						type: 'string',
						default: '',
						description: 'Agent UUID',
					},
					{
						displayName: 'UUIDs',
						name: 'uuids',
						type: 'string',
						default: '',
						description: 'List of Agent UUIDs to filter by (comma-separated)',
					},
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
				if (resource === 'agent') {
					if (operation === 'getAgents') {
						const returnAll = this.getNodeParameter('returnAll', i) as boolean;
						const filters = this.getNodeParameter('filters', i) as {
							accountIds?: string;
							agentVersions?: string;
							computerName__contains?: string;
							countOnly?: boolean;
							domains?: string;
							externalIp__contains?: string;
							groupIds?: string;
							infected?: boolean;
							isActive?: boolean;
							isPendingUninstall?: boolean;
							isUpToDate?: boolean;
							lastActiveDate__between?: string;
							lastLoggedInUserName__contains?: string;
							machineTypes?: string[];
							networkStatuses?: string[];
							osTypes?: string[];
							query?: string;
							registeredAt__between?: string;
							scanStatuses?: string[];
							siteIds?: string;
							sortBy?: string;
							sortOrder?: string;
							uuid?: string;
							uuids?: string;
						};

						const qs: Record<string, string | number | boolean> = {};

						// Add filters to query string
						if (filters.accountIds) qs.accountIds = filters.accountIds;
						if (filters.agentVersions) qs.agentVersions = filters.agentVersions;
						if (filters.computerName__contains) qs['computerName__contains'] = filters.computerName__contains;
						if (filters.countOnly) qs.countOnly = filters.countOnly;
						if (filters.domains) qs.domains = filters.domains;
						if (filters.externalIp__contains) qs['externalIp__contains'] = filters.externalIp__contains;
						if (filters.groupIds) qs.groupIds = filters.groupIds;
						if (filters.infected) qs.infected = filters.infected;
						if (filters.isActive) qs.isActive = filters.isActive;
						if (filters.isPendingUninstall) qs.isPendingUninstall = filters.isPendingUninstall;
						if (filters.isUpToDate) qs.isUpToDate = filters.isUpToDate;
						if (filters.lastActiveDate__between) qs['lastActiveDate__between'] = filters.lastActiveDate__between;
						if (filters.lastLoggedInUserName__contains) qs['lastLoggedInUserName__contains'] = filters.lastLoggedInUserName__contains;
						if (filters.machineTypes?.length) qs.machineTypes = filters.machineTypes.join(',');
						if (filters.networkStatuses?.length) qs.networkStatuses = filters.networkStatuses.join(',');
						if (filters.osTypes?.length) qs.osTypes = filters.osTypes.join(',');
						if (filters.query) qs.query = filters.query;
						if (filters.registeredAt__between) qs['registeredAt__between'] = filters.registeredAt__between;
						if (filters.scanStatuses?.length) qs.scanStatuses = filters.scanStatuses.join(',');
						if (filters.siteIds) qs.siteIds = filters.siteIds;
						if (filters.sortBy) qs.sortBy = filters.sortBy;
						if (filters.sortOrder) qs.sortOrder = filters.sortOrder;
						if (filters.uuid) qs.uuid = filters.uuid;
						if (filters.uuids) qs.uuids = filters.uuids;

						let responseData: { data: object[]; pagination?: { nextCursor?: string } };
						const allData: object[] = [];

						if (returnAll) {
							qs.limit = 1000;
							do {
								responseData = await this.helpers.httpRequestWithAuthentication.call(
									this,
									'sentinelOneApi',
									{
										method: 'GET' as IHttpRequestMethods,
										url: `${baseUrl}/web/api/v2.1/agents`,
										qs,
										json: true,
									},
								);

								if (responseData.data) {
									allData.push(...responseData.data);
								}

								if (responseData.pagination?.nextCursor) {
									qs.cursor = responseData.pagination.nextCursor;
								}
							} while (responseData.pagination?.nextCursor);

							for (const agent of allData) {
								returnData.push({ json: agent });
							}
						} else {
							const limit = this.getNodeParameter('limit', i) as number;
							qs.limit = limit;

							responseData = await this.helpers.httpRequestWithAuthentication.call(
								this,
								'sentinelOneApi',
								{
									method: 'GET' as IHttpRequestMethods,
									url: `${baseUrl}/web/api/v2.1/agents`,
									qs,
									json: true,
								},
							);

							if (responseData.data) {
								for (const agent of responseData.data) {
									returnData.push({ json: agent });
								}
							}
						}
					}
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message } });
					continue;
				}
				throw new NodeApiError(this.getNode(), error as object);
			}
		}

		return [returnData];
	}
}

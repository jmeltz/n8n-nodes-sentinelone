import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class SentinelOneApi implements ICredentialType {
	name = 'sentinelOneApi';
	displayName = 'SentinelOne API';
	documentationUrl = 'https://developer.sentinelone.com/';
	properties: INodeProperties[] = [
		{
			displayName: 'API URL',
			name: 'apiUrl',
			type: 'string',
			default: '',
			placeholder: 'https://usea1-partners.sentinelone.net',
			description: 'The base URL of your SentinelOne console (e.g., https://usea1-partners.sentinelone.net)',
			required: true,
		},
		{
			displayName: 'API Token',
			name: 'apiToken',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			description: 'The API token for authentication. Generate this from Settings > Users > API Token in your SentinelOne console.',
			required: true,
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=ApiToken {{$credentials.apiToken}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.apiUrl}}',
			url: '/web/api/v2.1/system/info',
			method: 'GET',
		},
	};
}

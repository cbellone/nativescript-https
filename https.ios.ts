// 

import * as application from 'application'
import { HttpRequestOptions, Headers, HttpResponse } from 'http'
import { isDefined, isNullOrUndefined, isObject } from 'utils/types'
import * as Https from './https.common'



interface Ipolicies {
	def: AFSecurityPolicy
	secured: boolean
	secure?: AFSecurityPolicy
}
let policies: Ipolicies = {
	def: AFSecurityPolicy.defaultPolicy(),
	secured: false,
}

export function enableSSLPinning(options: Https.HttpsSSLPinningOptions) {
	policies.secure = CustomAFSecurityPolicy.policyWithPinningMode(AFSSLPinningMode.PublicKey)
	let allowInvalidCertificates = (isDefined(options.allowInvalidCertificates)) ? options.allowInvalidCertificates : false
	policies.secure.allowInvalidCertificates = allowInvalidCertificates
	let validatesDomainName = (isDefined(options.validatesDomainName)) ? options.validatesDomainName : true
	policies.secure.validatesDomainName = validatesDomainName
	let data = NSData.dataWithContentsOfFile(options.certificate)
	policies.secure.pinnedCertificates = NSSet.setWithObject(data)
	policies.secured = true
	console.log('nativescript-https > Enabled SSL pinning')
}
export function disableSSLPinning() {
	policies.secured = false
	console.log('nativescript-https > Disabled SSL pinning')
}
console.info('nativescript-https > Disabled SSL pinning by default')



function AFSuccess(resolve, task: NSURLSessionDataTask, data: NSDictionary<string, any> & NSData & NSArray<any>) {
	let content: any
	if (data && data.class) {
		if (data.enumerateKeysAndObjectsUsingBlock || data.class().name == 'NSArray') {
			let serial = NSJSONSerialization.dataWithJSONObjectOptionsError(data, NSJSONWritingOptions.PrettyPrinted)
			content = NSString.alloc().initWithDataEncoding(serial, NSUTF8StringEncoding).toString()
		} else if (data.class().name == 'NSData') {
			content = NSString.alloc().initWithDataEncoding(data, NSASCIIStringEncoding).toString()
		} else {
			content = data
		}


	} else {
		content = data
	}

	resolve({ task, content })
}

function AFFailure(resolve, reject, task: NSURLSessionDataTask, error: NSError) {
	let data: NSData = error.userInfo.valueForKey(AFNetworkingOperationFailingURLResponseDataErrorKey)
	let body = NSString.alloc().initWithDataEncoding(data, NSUTF8StringEncoding).toString()
	let content: any = {
		body,
		description: error.description,
		reason: error.localizedDescription,
		url: error.userInfo.objectForKey('NSErrorFailingURLKey').description
	}
	if (policies.secured == true) {
		content.description = 'nativescript-https > Invalid SSL certificate! ' + content.description
	}
	let reason = error.localizedDescription
	reject({ task, content, reason })
}

export function request(opts: Https.HttpsRequestOptions): Promise<Https.HttpsResponse> {
	return new Promise(function(resolve, reject) {
		try {

			let manager = AFHTTPSessionManager.manager()
			let cTypeJSON = opts.headers && opts.headers['Content-Type'] == 'application/json';
			if (cTypeJSON) {
				manager.requestSerializer = AFJSONRequestSerializer.serializer()
			} else {
				manager.requestSerializer = AFHTTPRequestSerializer.serializer()
			}
			manager.responseSerializer = AFHTTPResponseSerializer.serializer()
			manager.requestSerializer.allowsCellularAccess = true
			manager.securityPolicy = (policies.secured == true) ? policies.secure : policies.def
			manager.requestSerializer.timeoutInterval = 10

			let heads = opts.headers
			if (heads) {
				Object.keys(heads).forEach(function(key) {
					manager.requestSerializer.setValueForHTTPHeaderField(heads[key] as any, key)
				})
			}

			let methods = {
				'GET': 'GETParametersSuccessFailure',
				'POST': 'POSTParametersSuccessFailure',
				'PUT': 'PUTParametersSuccessFailure',
				'DELETE': 'DELETEParametersSuccessFailure',
				'PATCH': 'PATCHParametersSuccessFailure',
				'HEAD': 'HEADParametersSuccessFailure',
			}
			manager[methods[opts.method]](opts.url, serializeBody(opts.body, cTypeJSON), function success(task: NSURLSessionDataTask, data: any) {
				AFSuccess(resolve, task, data)
			}, function failure(task, error) {
				AFFailure(resolve, reject, task, error)
			})

		} catch (error) {
			reject(error)
		}

	}).then(function(AFResponse: {
		task: NSURLSessionDataTask
		content: any
		reason?: string
	}) {

		let sendi: Https.HttpsResponse = {
			content: AFResponse.content,
			headers: {},
		}

		let response = AFResponse.task.response as NSHTTPURLResponse
		if (!isNullOrUndefined(response)) {
			sendi.statusCode = response.statusCode
			let dict = response.allHeaderFields
			dict.enumerateKeysAndObjectsUsingBlock(function(k, v) {
				sendi.headers[k] = v
			})
		}

		if (AFResponse.reason) {
			sendi.reason = AFResponse.reason
		}
		return Promise.resolve(sendi)

	})

}

function serializeBody(body: any, isJSON: boolean) {
	if (body) {
		if(body.constructor === Array && isJSON) {
			let arr = NSArray.new<any>();
			(<Array<any>>body).forEach(e => {
				let dict = NSMutableDictionary.new<string, any>()
				Object.keys(body).forEach(function(key) {
					dict.setValueForKey(body[key] as any, key)
				})
				return dict;
			});
			return arr;
		} else if (isObject(body)) {
			let dict = NSMutableDictionary.new<string, any>()
			Object.keys(body).forEach(function(key) {
				dict.setValueForKey(body[key] as any, key)
			})
			return dict;
		}
	}
	return null;
}

export class CustomAFSecurityPolicy extends AFSecurityPolicy {
	evaluateServerTrustForDomain(serverTrust: any, domain: string): boolean {
		console.log(`authorizing domain: ${domain}`);
		return true;
	}
}

export * from './https.common'
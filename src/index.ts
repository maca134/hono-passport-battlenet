import { Context } from "hono";
import { HonoPassportStrategy, PassportError } from "@maca134/hono-passport";
import { OAuth2StrategyOptions, oauth2Strategy } from "@maca134/hono-passport-oauth2";


export type BNetStrategyOptions = {
	clientID: string;
	clientSecret: string;
	returnURL: string;
	store?: OAuth2StrategyOptions['store'];
};

export type BNetUserInfo = {
	id: number;
	battletag: string;
	sub: string;
};

export function bnetStrategy<TUser>(
	options: BNetStrategyOptions,
	validate: (
		ctx: Context,
		info: BNetUserInfo,
	) => Promise<TUser | undefined>,
): HonoPassportStrategy<TUser> {
	const strategy = oauth2Strategy(
		{
			authorizeURL: 'https://oauth.battle.net/authorize',
			tokenURL: 'https://oauth.battle.net/token',
			clientID: options.clientID,
			clientSecret: options.clientSecret,
			returnURL: options.returnURL,
			state: true,
			store: options.store,
		},
		async (ctx, token) => {
			const response = await fetch('https://oauth.battle.net/userinfo', {
				headers: {
					Authorization: `Bearer ${token.access_token}`,
				},
			});
			if (response.status === 401) {
				throw new PassportError('Invalid token');
			}
			if (response.status !== 200) {
				throw new PassportError('Failed to fetch user info');
			}
			const info = await response.json() as BNetUserInfo;
			return validate(ctx, info);
		},
	);
	return {
		...strategy,
		name: 'battlenet',
	};
}
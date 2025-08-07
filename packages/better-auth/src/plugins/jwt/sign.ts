import { importJWK, SignJWT } from "jose";
import type { GenericEndpointContext } from "../../types";
import { BetterAuthError } from "../../error";
import { symmetricDecrypt, symmetricEncrypt } from "../../crypto";
import { generateExportedKeyPair, type JwtOptions } from ".";
import type { Jwk } from "./schema";
import { getJwksAdapter } from "./adapter";

export async function getJwtToken(
	ctx: GenericEndpointContext,
	options?: JwtOptions,
) {
	const adapter = getJwksAdapter(ctx.context.adapter);

	let key = await adapter.getLatestKey();
	const privateKeyEncryptionEnabled =
		!options?.jwks?.disablePrivateKeyEncryption;

	if (key === undefined) {
		const alg = options?.jwks?.keyPairConfig?.alg || "EdDSA";

		const { publicWebKey, privateWebKey } =
			await generateExportedKeyPair(options);
		const stringifiedPrivateWebKey = JSON.stringify(privateWebKey);

		let jwk: Partial<Jwk> = {
			publicKey: JSON.stringify({ alg, ...publicWebKey }),
			privateKey: privateKeyEncryptionEnabled
				? JSON.stringify(
						await symmetricEncrypt({
							key: ctx.context.secret,
							data: stringifiedPrivateWebKey,
						}),
					)
				: stringifiedPrivateWebKey,
			createdAt: new Date(),
		};

		key = await adapter.createJwk(jwk as Jwk);
	}

	let privateWebKey = privateKeyEncryptionEnabled
		? await symmetricDecrypt({
				key: ctx.context.secret,
				data: JSON.parse(key.privateKey),
			}).catch(() => {
				throw new BetterAuthError(
					"Failed to decrypt private private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either cleanup your jwks or disable private key encryption.",
				);
			})
		: key.privateKey;

	const privateKey = await importJWK(
		JSON.parse(privateWebKey),
		options?.jwks?.keyPairConfig?.alg ?? "EdDSA",
	);

	const session = ctx.context.session!;
	const baseURL = ctx.context.options.baseURL!;

	const payload = !options?.jwt?.definePayload
		? session.user
		: await options?.jwt.definePayload(session);

	const issuer =
		typeof options?.jwt?.issuer === "function"
			? await options.jwt.issuer(session)
			: options?.jwt?.issuer;

	const audience =
		typeof options?.jwt?.audience === "function"
			? await options.jwt.audience(session)
			: options?.jwt?.audience;

	const subject = options?.jwt?.getSubject
		? await options.jwt.getSubject(session)
		: typeof options?.jwt?.subject === "function"
			? await options.jwt.subject(session)
			: options?.jwt?.subject;

	const jwt = await new SignJWT(payload)
		.setProtectedHeader({
			alg: options?.jwks?.keyPairConfig?.alg ?? "EdDSA",
			kid: key.id,
		})
		.setIssuer(issuer ?? baseURL)
		.setSubject(subject ?? session.user.id)
		.setAudience(audience ?? baseURL)
		.setExpirationTime(options?.jwt?.expirationTime ?? "15m")
		.setIssuedAt()
		.sign(privateKey);
	return jwt;
}

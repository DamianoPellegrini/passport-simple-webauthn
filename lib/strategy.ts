import { Strategy as PassportStrategy } from 'passport';
import * as webauthn from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  CredentialDeviceType,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';
import type { Request } from 'express';

/**
 * Info provided by the authenticator during registration
 */
export interface RegistrationInfo {
  counter: number;
  credentialID: Uint8Array;
  credentialPublicKey: Uint8Array;
  credentialType: 'public-key';
  userVerified: boolean;
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
}

/**
 * Represent what we need to be stored in a session like storage
 */
export interface SessionData<User extends { id: string }> {
  challenge: string;
  user?: User;
}

/**
 * Used to extract the challenge and user from the request.
 */
export type ChallengeExtractorFn<User extends { id: string }> = (
  req: Request,
) => SessionData<User>;

/**
 * Represent the user and the authenticator by the strategy
 */
export type UserWithAuthenticator<User extends { id: string }> = {
  user: User;
  authenticator: AuthenticatorDevice;
};

/**
 * Used to conclude the authentication process.
 *
 * Receives the user or error by client function
 */
export type ConcludeAuthenticationFn<
  User extends { id: string },
  Error = any,
> = (
  err?: Error,
  userWithAuthenticator?: UserWithAuthenticator<User>,
  info?: any,
) => void;

/**
 * Function provided by the developer to authenticate the user by passing its data and authenticator data.
 */
export type AuthenticationFn<User extends { id: string }, Error> = (
  req: Request,
  credentialId: string,
  userHandle: string,
  conclude?: ConcludeAuthenticationFn<User, Error>,
) =>
  | UserWithAuthenticator<User>
  | undefined
  | Promise<UserWithAuthenticator<User> | undefined>;

/**
 * Used to conclude the registration process.
 *
 * Receives the user or error by client function
 */
export type ConcludeRegistrationFn<User extends { id: string }, Error = any> = (
  err?: Error,
  user?: User,
  info?: any,
) => void;

/**
 * Function provided by the developer to register the user.
 */
export type RegistrationFn<User extends { id: string }, Error> = (
  req: Request,
  user: User,
  registrationInfo: RegistrationInfo,
  conclude?: ConcludeRegistrationFn<User, Error>,
) => User | undefined | Promise<User | undefined>;

/**
 * Options for the WebAuthN strategy
 */
export interface StrategyOptions<User extends { id: string }> {
  passReqToCallback?: boolean;
  extractor: ChallengeExtractorFn<User>;
  expectedRPID: string;
  expectedOrigin?: string;
  supportedAlgorithmIDs?: number[];
  requireUserVerification?: boolean;
}

/**
 * WebAuthN strategy for passport
 */
export class Strategy<
  User extends { id: string },
  Error = any,
> extends PassportStrategy {
  name = 'webauthn';
  constructor(
    private readonly options: StrategyOptions<User>,
    private readonly authenticationFn: AuthenticationFn<User, Error>,
    private readonly registrationFn: RegistrationFn<User, Error>,
  ) {
    super();
  }

  async authenticate(req: Request) {
    const body: AuthenticationResponseJSON | RegistrationResponseJSON =
      req.body;
    const { challenge, user } = this.options.extractor(req);

    const clientData = JSON.parse(
      Buffer.from(body.response.clientDataJSON, 'base64url').toString(),
    );

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;

    if (clientData.type === 'webauthn.create') {
      if (!user) {
        return this.fail({ message: 'User not in session' }, 404);
      }
      // Registration
      const registration = req.body as RegistrationResponseJSON;

      const registrationResponse = await webauthn.verifyRegistrationResponse({
        response: registration,
        expectedChallenge: challenge,
        expectedOrigin:
          this.options.expectedOrigin ?? req.headers.origin ?? req.hostname,
        expectedRPID: this.options.expectedRPID,
        supportedAlgorithmIDs: this.options.supportedAlgorithmIDs,
        requireUserVerification: this.options.requireUserVerification,
      });

      function concludeRegistration(err?: Error, user?: User, info?: any) {
        if (err) return self.error(err);
        if (!user) return self.fail(info);
        self.success(user, info);
      }

      if (!registrationResponse.registrationInfo) {
        return this.fail({ message: 'Registration failed.' }, 500);
      }

      // Choose between async/await or callback
      if (this.registrationFn.length < 4) {
        try {
          const newUser = await this.registrationFn(
            req,
            user,
            registrationResponse.registrationInfo,
          );

          if (!newUser) {
            return this.fail({ message: 'User not found' }, 404);
          }

          this.success(newUser);
        } catch (err) {
          return this.error(err);
        }
      } else {
        this.registrationFn(
          req,
          user,
          registrationResponse.registrationInfo,
          concludeRegistration,
        );
      }
    } else if (clientData.type === 'webauthn.get') {
      // Authentication
      const authentication = req.body as AuthenticationResponseJSON;

      const userHandle = authentication.response.userHandle;

      // se ci sono entrambi, controlla che siano uguali
      // se non ce user e userHandle, fallisci

      if (user && userHandle && user.id !== userHandle) {
        return this.fail(
          { message: 'User handle does not match session' },
          400,
        );
      } else if (!userHandle) {
        return this.fail({ message: 'User handle not present' }, 400);
      }

      // Helper inline function to verify the authenticator
      async function verifyAuthenticator(authenticator: AuthenticatorDevice) {
        return await webauthn.verifyAuthenticationResponse({
          authenticator,
          response: authentication,
          expectedChallenge: challenge,
          expectedOrigin:
            self.options.expectedOrigin ?? req.headers.origin ?? req.hostname,
          expectedRPID: self.options.expectedRPID,
          requireUserVerification: self.options.requireUserVerification,
        });
      }

      // conclude authentication by verifying the authenticator
      async function concludeAuthentication(
        err?: Error,
        userWithAuthenticator?: UserWithAuthenticator<User>,
        info?: any,
      ) {
        if (err) return self.error(err);
        if (!userWithAuthenticator) return self.fail(info);

        try {
          if (
            !(await verifyAuthenticator(userWithAuthenticator.authenticator))
          ) {
            return self.fail(
              { message: 'Authenticator verification failed' },
              400,
            );
          }
        } catch (err) {
          console.error(err);
          return self.error(err);
        }

        self.success(userWithAuthenticator.user, info);
      }

      // Choose between async/await or callback
      if (this.authenticationFn.length < 4) {
        try {
          const userWithAuthenticator = await this.authenticationFn(
            req,
            body.id,
            user?.id ?? userHandle,
          );

          if (!userWithAuthenticator) {
            return this.fail({ message: 'Invelid credential' }, 400);
          }

          if (
            !(await verifyAuthenticator(userWithAuthenticator.authenticator))
          ) {
            return this.fail(
              { message: 'Authenticator verification failed' },
              400,
            );
          }

          this.success(userWithAuthenticator.user);
        } catch (err) {
          return this.error(err);
        }
      } else {
        this.authenticationFn(
          req,
          body.id,
          user?.id ?? userHandle,
          concludeAuthentication,
        );
      }
    } else {
      // Unsupported response type
      return this.fail(
        { message: 'Unsupported response type: ' + clientData.type },
        400,
      );
    }
  }
}

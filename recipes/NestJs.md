# NestJS implementation

> Note: session must be configured in the application and passport for this to work!

```ts
import { BadRequestException, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { UserService } from '../../user/user.service';
import { Strategy, RegistrationInfo } from 'passport-simple-webauthn';

@Injectable()
export class WebAuthNStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly userService: UserService) {
    super({
      extractor: (req: Request) => req.session.webauthn,
      expectedRPID: 'localhost',
      requireUserVerification: false,
    });

    // Force this to be bound to the strategy instance
    (this as any).authenticationFn = this.login;
    // Override validate (aka the last callback in constructor)
    (this as any).registrationFn = this.register;
  }

  async register(
    req: Request,
    user: { id: string; username: string; displayName: string },
    registrationInfo: RegistrationInfo,
  ) {
    return await this.userService.create({
      ...user,
      id: user.id,
      credentials: [
        {
          credentialId: Buffer.from(registrationInfo.credentialID),
          publicKey: Buffer.from(registrationInfo.credentialPublicKey),
          signCount: registrationInfo.counter,
          backedUp: registrationInfo.credentialBackedUp,
          deviceType: registrationInfo.credentialDeviceType,
        },
      ],
    });
  }

  async login(req: Request, credentialId: string, userHandle: string) {
    const user = await this.userService.findOne({
      where: {
        id: userHandle,
      },
      relations: ['credentials'],
    });

    const credential = user?.credentials.find(
      (c) => Buffer.from(c.credentialId).toString('base64url') === credentialId,
    );

    if (!(user && credential)) {
      throw new BadRequestException('Invalid key');
    }

    return {
      user,
      authenticator: {
        counter: credential.signCount,
        credentialID: credential.credentialId,
        credentialPublicKey: credential.publicKey,
      },
    };
  }
}
```

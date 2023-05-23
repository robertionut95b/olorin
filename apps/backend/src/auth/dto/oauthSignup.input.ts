import { Field } from '@nestjs/graphql';
import { SignupInput } from './signup.input';
import { IsNotEmpty } from 'class-validator';

export class OauthSignupInput extends SignupInput {
  @Field()
  @IsNotEmpty()
  id: string;
}

import { JwtDto } from './jwt.dto';

export interface RefreshJwtDto extends JwtDto {
  tokenId: string;
}

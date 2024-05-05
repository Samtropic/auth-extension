import { InvalidatedRefreshTokenError } from './invalidated-refresh-token-error';

describe('InvalidatedRefreshTokenError', () => {
  it('should be defined', () => {
    expect(new InvalidatedRefreshTokenError()).toBeDefined();
  });
});

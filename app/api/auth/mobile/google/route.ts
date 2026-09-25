import { NextRequest, NextResponse } from 'next/server';
import { OAuth2Client } from 'google-auth-library';
import { encode } from 'next-auth/jwt';
import { upsertOAuthUser } from '@/lib/auth/oauth-user';
import { authOptions } from '@/lib/auth/config';

const client = new OAuth2Client();

/**
 * POST /api/auth/mobile/google
 *
 * Mobile equivalent of the web Google sign-in path: the app gets an ID
 * token from Google via expo-auth-session, sends it here, we verify it
 * server-side (never trust a client-supplied token without verification)
 * and find-or-create the matching User.
 *
 * Issues a NextAuth-compatible JWT that the mobile client can use as a
 * Bearer token on subsequent authenticated API calls.
 */
export async function POST(req: NextRequest) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    return NextResponse.json({ error: 'Google sign-in is not configured' }, { status: 501 });
  }

  const body = await req.json().catch(() => null);
  const idToken = typeof body?.idToken === 'string' ? body.idToken : '';
  if (!idToken) {
    return NextResponse.json({ error: 'idToken is required' }, { status: 422 });
  }

  let payload;
  try {
    const ticket = await client.verifyIdToken({ idToken, audience: clientId });
    payload = ticket.getPayload();
  } catch {
    return NextResponse.json({ error: 'Invalid Google token' }, { status: 401 });
  }

  if (!payload?.email) {
    return NextResponse.json({ error: 'Google account has no email' }, { status: 422 });
  }

  const user = await upsertOAuthUser({
    email: payload.email,
    name: payload.name,
    image: payload.picture,
  });

  // Issue a NextAuth-compatible JWT token that the mobile client can use
  // as a Bearer token on subsequent API calls. The token is encoded using
  // the same secret and encryption settings as the web session, so
  // getServerSession(authOptions) will decode it transparently.
  const token = await encode({
    token: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      emailVerified: user.emailVerified?.toISOString() ?? null,
      onboardingCompleted: !!user.onboardingCompletedAt,
    },
    secret: process.env.NEXTAUTH_SECRET ?? process.env.AUTH_SECRET ?? '',
    maxAge: 30 * 24 * 60 * 60, // 30 days — matches NextAuth default
  });

  return NextResponse.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      walletAddress: user.walletAddress,
      onboardingCompleted: !!user.onboardingCompletedAt,
    },
    // Include token type and expiry for mobile client convenience
    tokenType: 'Bearer',
    expiresIn: 30 * 24 * 60 * 60, // seconds
  });
}

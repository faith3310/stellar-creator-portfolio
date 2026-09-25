import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { randomUUID } from 'crypto';
import { prisma } from '@/lib/prisma';
import { hashPassword } from '@/lib/auth/config';
import { submitQueuedEmail } from '@/lib/notifications';

const registerSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(200),
  name: z.string().min(1).max(100).optional(),
});

/**
 * POST /api/auth/register — email/password account creation.
 *
 * Creates the user with an unverified email, generates a verification
 * token, and sends a verification email with a link to
 * /api/auth/verify-email. The user must click the link before they
 * can sign in (the credentials provider checks emailVerified).
 */
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  const parsed = registerSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid input', details: parsed.error.flatten().fieldErrors },
      { status: 422 },
    );
  }
  const { email, password, name } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json({ error: 'An account with this email already exists' }, { status: 409 });
  }

  // Create user with UNVERIFIED email
  const user = await prisma.user.create({
    data: {
      email,
      name: name ?? null,
      password: hashPassword(password),
      emailVerified: null,
    },
  });

  // Generate a verification token (expires in 24 hours)
  const token = randomUUID();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await prisma.verificationToken.create({
    data: {
      identifier: email,
      token,
      expires,
    },
  });

  // Send verification email
  const appUrl = process.env.NEXTAUTH_URL ?? 'http://localhost:3000';
  const verifyUrl = `${appUrl}/api/auth/verify-email?token=${token}`;

  try {
    await submitQueuedEmail({
      userId: user.id,
      to: email,
      subject: 'Verify your email — Stellar Creator Portfolio',
      template: 'email-verification',
      category: 'transactional',
      variables: {
        name: name ?? email,
        headline: 'Verify your email address',
        bodyText: 'Welcome! Please verify your email to activate your account and start signing in.',
        actionUrl: verifyUrl,
        actionLabel: 'Verify Email',
        footerNote: 'This link expires in 24 hours. If you did not create an account, you can safely ignore this email.',
      },
    });
  } catch (err) {
    console.error('[Register] Failed to send verification email:', err);
    // Don't fail registration if email sending fails — the user can
    // request a resend from the login page.
  }

  return NextResponse.json({
    success: true,
    message: 'Account created. Check your email for a verification link.',
  });
}

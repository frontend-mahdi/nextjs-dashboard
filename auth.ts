import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import type { User } from '@/app/lib/definitions';
import { db } from "@vercel/postgres";
import bcrypt from 'bcrypt';
import { z } from 'zod';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const client = await db.connect(); // Establish connection

    const result = await client.sql<User>`
      SELECT * FROM users WHERE email = ${email}
    `;

    client.release(); // Release the connection

    return result.rows.length > 0 ? result.rows[0] : undefined; // Return only a single user

  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
        
        if (!parsedCredentials.success) return null;

        const { email, password } = parsedCredentials.data;
        const user = await getUser(email);
        
        if (!user || !user.password) return null; // Ensure password exists
        
        const passwordsMatch = await bcrypt.compare(password, user.password);
        
        if (passwordsMatch) return user;
        
        return null;
      },
    }),
  ],
});

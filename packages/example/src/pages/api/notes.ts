import type { APIRoute } from 'astro';
import { objectRef, touch, user, whoami, writeTuples } from '../../lib/authz';
import { createNote } from '../../lib/notes';

// Create a note the caller owns: store the body (app-owned data) and write the
// ownership tuple so authz knows who may view/edit it.
export const POST: APIRoute = async ({ request, locals, redirect }) => {
    const env = locals.runtime.env;
    const userId = await whoami(request, env);
    if (!userId) return new Response('Unauthorized', { status: 401 });

    const form = await request.formData();
    const title = String(form.get('title') || '').slice(0, 200);
    const body = String(form.get('body') || '').slice(0, 2000);
    if (!title) return new Response('Title required', { status: 400 });

    const id = crypto.randomUUID();
    await createNote(env.NOTES, { id, title, body, ownerId: userId });
    await writeTuples(request, env, [touch(objectRef('note', id), 'owner', user(userId))]);

    return redirect('/app');
};

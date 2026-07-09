import type { APIRoute } from 'astro';
import { authzClient, objectRef, touch, user, whoami, writeTuples } from '../../lib/authz';

// Share a note: only its owner may add a viewer. We verify ownership with an
// authz `edit` check (owner-only per the schema) before writing the viewer tuple.
export const POST: APIRoute = async ({ request, locals, redirect }) => {
    const env = locals.runtime.env;
    const userId = await whoami(request, env);
    if (!userId) return new Response('Unauthorized', { status: 401 });

    const form = await request.formData();
    const noteId = String(form.get('noteId') || '');
    const target = String(form.get('userId') || '').trim();
    if (!noteId || !target) return new Response('noteId and userId required', { status: 400 });

    const { allowed } = await authzClient(env).check(request, { type: 'note', id: noteId, permission: 'edit' });
    if (!allowed) return new Response('Forbidden', { status: 403 });

    await writeTuples(request, env, [touch(objectRef('note', noteId), 'viewer', user(target))]);
    return redirect('/app');
};

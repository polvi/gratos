// Tiny KV-backed note store. The app owns this data (keyed by the AuthGravity
// user UUID); AuthGravity only decides who may view/edit each note.

export interface Note {
    id: string;
    title: string;
    body: string;
    ownerId: string;
}

const INDEX_KEY = 'note-index';

export async function listIds(kv: KVNamespace): Promise<string[]> {
    return JSON.parse((await kv.get(INDEX_KEY)) || '[]');
}

export async function getNote(kv: KVNamespace, id: string): Promise<Note | null> {
    const v = await kv.get(`note:${id}`);
    return v ? (JSON.parse(v) as Note) : null;
}

export async function createNote(kv: KVNamespace, note: Note): Promise<void> {
    await kv.put(`note:${note.id}`, JSON.stringify(note));
    const ids = await listIds(kv);
    ids.push(note.id);
    await kv.put(INDEX_KEY, JSON.stringify(ids));
}

// Object/subject references and shared error type.
//
// String forms used throughout the API:
//   object:  "type:id"              e.g. "document:readme"
//   subject: "type:id"              e.g. "user:6f3c9a..."
//            "type:id#relation"     e.g. "group:eng#member" (subject set)

export type ObjectRef = { type: string; id: string };
export type SubjectRef = { type: string; id: string; relation?: string };

// Type/relation/permission names.
export const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
// Object/subject ids. ':' and '#' are excluded so string refs parse
// unambiguously; '/' is allowed for path-like ids.
export const ID_RE = /^[a-zA-Z0-9_@.\/=+-]{1,128}$/;

export class ApiError extends Error {
    status: 400 | 401 | 403 | 404 | 409 | 422;
    details?: string[];

    constructor(status: ApiError['status'], message: string, details?: string[]) {
        super(message);
        this.status = status;
        this.details = details;
    }
}

/** Parse "type:id" into an ObjectRef. Throws ApiError(400) on malformed input. */
export function parseObjectRef(s: unknown, field = 'object'): ObjectRef {
    if (typeof s !== 'string') throw new ApiError(400, `${field} must be a string like "type:id"`);
    const idx = s.indexOf(':');
    if (idx === -1) throw new ApiError(400, `${field} "${s}" must look like "type:id"`);
    const type = s.slice(0, idx);
    const id = s.slice(idx + 1);
    if (!NAME_RE.test(type)) throw new ApiError(400, `${field} type "${type}" is invalid`);
    if (!ID_RE.test(id)) throw new ApiError(400, `${field} id "${id}" is invalid`);
    return { type, id };
}

/** Parse "type:id" or "type:id#relation" into a SubjectRef. */
export function parseSubjectRef(s: unknown, field = 'subject'): SubjectRef {
    if (typeof s !== 'string') throw new ApiError(400, `${field} must be a string like "type:id" or "type:id#relation"`);
    const hash = s.indexOf('#');
    let relation: string | undefined;
    let base = s;
    if (hash !== -1) {
        relation = s.slice(hash + 1);
        base = s.slice(0, hash);
        if (!NAME_RE.test(relation)) throw new ApiError(400, `${field} relation "${relation}" is invalid`);
    }
    const { type, id } = parseObjectRef(base, field);
    return relation ? { type, id, relation } : { type, id };
}

export function fmtObject(o: ObjectRef): string {
    return `${o.type}:${o.id}`;
}

export function fmtSubject(s: SubjectRef): string {
    return s.relation ? `${s.type}:${s.id}#${s.relation}` : `${s.type}:${s.id}`;
}

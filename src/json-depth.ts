import { ModerationRejectError } from './errors.js';
export function assertJsonDepth(value: unknown, max = 32): void {
    const stack: Array<[
        unknown,
        number
    ]> = [[value, 0]];
    while (stack.length) {
        const [v, d] = stack.pop()!;
        if (d > max)
            throw new ModerationRejectError(400, 'JSON depth exceeded.');
        if (v && typeof v === 'object')
            for (const item of Object.values(v))
                stack.push([item, d + 1]);
    }
}

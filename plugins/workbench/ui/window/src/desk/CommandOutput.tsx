import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';

/** A command keeps its own scroll position; following is the reader's choice. */
export function CommandOutput({ children, className, label, onFollowChange, earlier = 0, onEarlier, initialFollowing = true, freezeWhilePaused = false }: {
  children: ReactNode;
  className: string;
  label: string;
  onFollowChange?: (following: boolean) => void;
  earlier?: number;
  onEarlier?: () => void;
  initialFollowing?: boolean;
  freezeWhilePaused?: boolean;
}) {
  const body = useRef<HTMLDivElement>(null);
  const following = useRef(initialFollowing);
  const lastTop = useRef(0);
  const [paused, setPaused] = useState(!initialFollowing);
  const shown = useRef(children);
  if (!paused || !freezeWhilePaused) shown.current = children;
  const follow = (value: boolean) => {
    if (following.current === value) return;
    following.current = value;
    setPaused(!value);
    onFollowChange?.(value);
  };
  useLayoutEffect(() => {
    const element = body.current;
    if (!element || !following.current) return;
    element.scrollTop = element.scrollHeight;
    lastTop.current = element.scrollTop;
  });

  return (
    <div className="ct-output-wrap">
      {earlier > 0 && onEarlier && <button type="button" className="ct-more ct-output-earlier" onClick={() => {
        follow(false);
        onEarlier();
      }}>{earlier} earlier lines</button>}
      <div ref={body} className={`${className} ct-output-scroll`} tabIndex={0} role="region" aria-label={label}
        onWheel={(event) => { if (event.deltaY < 0) follow(false); }}
        onKeyDown={(event) => {
          if (event.target !== event.currentTarget) return;
          if (['ArrowUp', 'PageUp', 'Home'].includes(event.key)) follow(false);
        }}
        onPointerDown={(event) => {
          // Freeze output while selecting text or dragging the scrollbar.
          if (event.button === 0 && event.currentTarget.scrollHeight > event.currentTarget.clientHeight) follow(false);
        }}
        onScroll={(event) => {
          const element = event.currentTarget;
          const top = element.scrollTop;
          if (top < lastTop.current - 1) follow(false);
          else if (top > lastTop.current && element.scrollHeight - top - element.clientHeight < 2) follow(true);
          lastTop.current = top;
        }}>
        {shown.current}
      </div>
      {paused && <button type="button" className="ct-act ct-output-follow" onClick={() => {
        follow(true);
        const element = body.current;
        if (element) {
          element.scrollTop = element.scrollHeight;
          lastTop.current = element.scrollTop;
        }
      }}>Follow output ↓</button>}
    </div>
  );
}

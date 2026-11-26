import { useEffect, useRef, useState, type ReactNode } from 'react';
import { animate, motion, useAnimationControls, useReducedMotion } from 'motion/react';

export function PageMotion({ page, children }: { page: string; children: ReactNode }) {
  const controls = useAnimationControls();
  const reduce = useReducedMotion();
  useEffect(() => {
    if (reduce) { controls.set({ opacity: 1, y: 0 }); return; }
    controls.set({ opacity: .82, y: 4 });
    void controls.start({ opacity: 1, y: 0, transition: { duration: .14 } });
    return () => controls.stop();
  }, [controls, page, reduce]);
  return <motion.div className="page-motion" initial={false} animate={controls}>{children}</motion.div>;
}

export function MotionCard({ index, children, label }: { index: number; children: ReactNode; label: string }) {
  const reduce = useReducedMotion();
  return <motion.section className="panel overview-card" aria-label={label} initial={reduce ? false : { opacity: 0, y: 5 }}
    animate={{ opacity: 1, y: 0 }} transition={{ duration: .15, delay: reduce ? 0 : index * .035 }}>{children}</motion.section>;
}

export function AnimatedCount({ value }: { value: number }) {
  const [display, setDisplay] = useState(value);
  const last = useRef(value);
  const reduce = useReducedMotion();
  useEffect(() => {
    if (reduce) { last.current = value; setDisplay(value); return; }
    const animation = animate(last.current, value, {
      duration: .2, onUpdate: (next) => { last.current = next; setDisplay(Math.round(next)); },
    });
    return () => animation.stop();
  }, [reduce, value]);
  return <span aria-label={value.toLocaleString()}>{display.toLocaleString()}</span>;
}

export function ChartBar({ ratio }: { ratio: number }) {
  const reduce = useReducedMotion();
  return <motion.span className="chart-bar-fill" initial={reduce ? false : { scaleY: 0 }}
    animate={{ scaleY: ratio }} transition={{ duration: reduce ? 0 : .22 }} />;
}

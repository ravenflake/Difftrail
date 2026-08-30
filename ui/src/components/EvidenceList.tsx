import type { Evidence } from "../types";
import { Icon } from "./Icon";

export function EvidenceList({ items, counter = false }: { items: Evidence[]; counter?: boolean }) {
  if (!items.length) return null;
  return (
    <div className={`evidence-list ${counter ? "is-counter" : ""}`}>
      {items.map((item, index) => (
        <div className="evidence-item" key={`${item.signal}-${index}`}>
          <span className="evidence-mark"><Icon name={counter ? "alert" : "change"} size={13} /></span>
          <div>
            <div className="evidence-heading"><strong>{item.signal}</strong><span className={`signal-strength strength-${item.strength}`} title="Strength of this rule-based signal">{item.strength}</span></div>
            <p>{item.explanation}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

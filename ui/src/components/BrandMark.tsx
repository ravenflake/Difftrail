import type { SVGProps } from "react";

interface BrandMarkProps extends SVGProps<SVGSVGElement> {
  size?: number;
}

const brandAccent = "#d6b06e";

export function BrandMark({ size = 31, className, ...props }: BrandMarkProps) {
  return (
    <svg
      {...props}
      className={`brand-mark-svg${className ? ` ${className}` : ""}`}
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <g transform="translate(-4 0)" stroke="currentColor" strokeWidth="7.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M27 18V82H50C66 82 77 70 77 59" />
        <path d="M77 41C77 30 66 18 50 18H27" />
        <path d="M53 50H81" stroke={brandAccent} />
        <circle cx="81" cy="50" r="3.75" fill={brandAccent} stroke="none" />
      </g>
    </svg>
  );
}

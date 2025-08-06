import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-3 py-1 text-sm font-semibold transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 shadow-sm gap-1 min-h-[28px] sm:px-2.5 sm:py-0.5 sm:text-xs sm:min-h-[24px]",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-gradient-to-r from-blue-500 to-blue-600 text-primary-foreground hover:from-blue-600 hover:to-blue-700",
        secondary:
          "border-transparent bg-gradient-to-r from-gray-200 to-gray-300 text-secondary-foreground hover:from-gray-300 hover:to-gray-400",
        destructive:
          "border-transparent bg-gradient-to-r from-red-500 to-red-600 text-destructive-foreground hover:from-red-600 hover:to-red-700",
        outline: "text-foreground border-blue-200 hover:border-blue-400 hover:bg-blue-50",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }

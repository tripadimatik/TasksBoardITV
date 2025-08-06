import { cva } from "class-variance-authority"

export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 select-none transform-gpu will-change-transform",
  {
    variants: {
      variant: {
        default: "bg-blue-600 text-white hover:bg-blue-700 hover:scale-[1.02] active:bg-blue-800 active:scale-[0.98] focus:bg-blue-700 shadow-sm hover:shadow-md",
        destructive:
          "bg-red-600 text-white hover:bg-red-700 hover:scale-[1.02] active:bg-red-800 active:scale-[0.98] focus:bg-red-700 shadow-sm hover:shadow-md",
        outline:
          "border border-input bg-background hover:bg-accent hover:text-accent-foreground hover:scale-[1.02] active:bg-accent/80 active:scale-[0.98] shadow-sm hover:shadow-md",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 hover:scale-[1.02] active:bg-secondary/60 active:scale-[0.98] shadow-sm hover:shadow-md",
        ghost: "hover:bg-accent hover:text-accent-foreground hover:scale-[1.02] active:bg-accent/80 active:scale-[0.98]",
        link: "text-primary underline-offset-4 hover:underline hover:scale-[1.02] active:text-primary/80 active:scale-[0.98]",
      },
      size: {
        default: "h-12 px-6 py-3 text-base sm:h-10 sm:px-4 sm:py-2 sm:text-sm",
        sm: "h-10 px-4 py-2 text-sm sm:h-9 sm:px-3 sm:text-xs",
        lg: "h-14 px-8 py-4 text-lg sm:h-11 sm:px-8 sm:py-3 sm:text-base",
        icon: "h-12 w-12 sm:h-10 sm:w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)
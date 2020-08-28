; Name:               <name>
; Course:             COMP 252
; Instructor:         Dr. Conlon
; Date started:       <date>
; Last modification:  <date>
; Purpose of program: Program skeleton

    .CR 6502             ; Assemble 6502
    .LI on,toff          ; Listing on, no timings included
    .TF skeleton.prg,BIN ; Object filename and format

; Define some constants
space = $20 ; ASCII space
box   = 230 ; ASCII box
iovec = $8800
statr = $8801
ctrlr = $8802
cmdr  = iovec+3
mask  = %00011111 ; Binary bit mask

    .OR $0000 ; Start code at address $0000
    jmp start ; Jump to beginning of program

; Define zero-page storage
home    .DW $7000    ; Address of upper left on video screen
scrend  .DW $73e7    ; Address of bottom right of video screen
msg     .AZ "Error!" ; ASCII string
        .BS $0300-*  ; Skip to beginning of program

start   cld ; Set binary mode
        lda #$01
        sta $01
        adc #$09

        ;jsr $9090
        cld              ;775
        lda #$01
        sta $01
        adc #$09         ;780

        cld              ;782
        lda #$01
        sta $01
        adc #$09

        adc #$05 
        cld              ;789
        lda #$01
        sta $01
        adc #$09

        adc #$05         ;796 
  
        jsr $9090
        ;lda #$02
        ;sta $03
        ;adc #$08
        ;sub #$08
        ;cli

        ;lda #$02
        ;sta $02
        ;adc #$08
        ;sub #$08
        ;`cli

        ; pass
        ;brk
        .EN ; End of program

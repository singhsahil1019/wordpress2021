<?php
/**
 * Content for home page quote section
 *
 * @since 1.0.1
 *
 * @package Bizline WordPress theme
 */

$selected_page = bizline_get( 'home-quote-title-page' );
$href = bizline_get( 'home-quote-href' ) ? bizline_get( 'home-quote-href' ) : get_permalink( $selected_page );
if( bizline_get( 'home-quote-status' ) && $selected_page ) { ?>
	<section class="bizline-get-quote-section">
		<div class="container get-quote-container">
			<div class="get-quote-text">
				<h2><?php echo get_the_title( $selected_page ); ?></h2>
			</div>
			<div class="get-quote-btn">
				<a href="<?php echo esc_url( $href ); ?>" class="bizline-button-primary btn-get-quote"><?php echo esc_html( bizline_get( 'home-quote-button-text' ) ); ?></a>
			</div>
		</div>
	</section> <!-- get quote section -->
<?php }


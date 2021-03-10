<?php
/**
 * Comtent for header topbar
 *
 * @since 1.0.1
 *
 * @package Bizline WordPress Theme
 */

if( Bizline_Theme::topbar_has_content() ): ?>
  <div class="<?php echo esc_attr( Bizline_Helper::with_prefix( 'top-bar' ) ); ?>">
  	<div class="container">
  		<div class="row align-items-center">
  			<div class="col-12 col-md-8">
  				<div class="<?php echo esc_attr( Bizline_Helper::with_prefix( 'top-bar-info' ) ); ?>">
  					<ul>
  						<?php 
  							$data = array(
  								'location' => array(
  									'icon' => 'fa-map-marker',
  									'href' => false,
  									'id'   => 'enhanced-location'
  								),
  								'phone-num' => array(
  									'icon' => 'fa-phone',
  									'href' => 'tel:',
  									'id'   => 'enhanced-phone'
  								),
  								'email' => array(
  									'icon' => 'fa-envelope',
  									'href' => 'mailto:',
  									'id'   => 'enhanced-email'
  								),
  							);
                
 							foreach( $data as $setting => $d ){
 								$value = bizline_get( $setting );
 								$href = $d[ 'href' ] ? $d[ 'href' ] . $value : false;
 								if( !empty( $value ) ):?>							
 									<li>
 										<?php if( $href ) : ?>
 											<a href="<?php echo esc_attr( $href ); ?>">											
 												<i class="fa <?php echo esc_attr( $d[ 'icon' ] ); ?>"></i>
 												<span id="<?php echo esc_attr( $d[ 'id' ] ); ?>">
 													<?php echo esc_html( $value); ?>	
 												</span>
 											</a>
 										<?php else: ?>
 											<i class="fa <?php echo esc_attr( $d[ 'icon' ] ); ?>"></i> 
 											<span id="<?php echo esc_attr( $d[ 'id' ] ); ?>">
 												<?php echo esc_html( $value ); ?>	
 											</span>
 										<?php endif; ?>
 									</li>
 								<?php endif;
 							}
  						?>
  					</ul>
  				</div>
  			</div>
  			<?php if( bizline_get( 'header-social-menu' ) ) : ?>
	 			<div class="col-12 col-md-4">
	 				<div class="<?php echo esc_attr( Bizline_Helper::with_prefix( 'social-menu' ) ); ?>">
	 					<?php 
	 						Bizline_Helper::get_menu( 'social-menu-header', true )
	 					?>
	 				</div>
	 			</div>
 			<?php endif; ?>
  		</div>
  	</div>
  </div>
<?php endif; ?>